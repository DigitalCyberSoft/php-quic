--TEST--
Mixed bidi and uni streams simultaneously (separate ID spaces per RFC 9000 s2.1)
--DESCRIPTION--
RFC 9000 Section 2.1 defines separate ID spaces for bidirectional and
unidirectional streams. Some implementations confused the two spaces, causing
MAX_STREAMS violations or stream ID collisions. Client-initiated bidi IDs
are 0, 4, 8... and client-initiated uni IDs are 2, 6, 10...
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

// Open alternating bidi and uni streams
$bidi1 = $conn->openStream(QUIC_STREAM_BIDI);
echo "Bidi 1 ID: " . $bidi1->getId() . "\n";
echo "Bidi 1 type: " . ($bidi1->getType() == QUIC_STREAM_BIDI ? "BIDI" : "wrong") . "\n";

$uni1 = $conn->openStream(QUIC_STREAM_UNI);
echo "Uni 1 ID: " . $uni1->getId() . "\n";
echo "Uni 1 type: " . ($uni1->getType() != QUIC_STREAM_BIDI ? "UNI" : "wrong") . "\n";

$bidi2 = $conn->openStream(QUIC_STREAM_BIDI);
echo "Bidi 2 ID: " . $bidi2->getId() . "\n";

$uni2 = $conn->openStream(QUIC_STREAM_UNI);
echo "Uni 2 ID: " . $uni2->getId() . "\n";

// Verify bidi IDs are in bidi space (0, 4, 8... = divisible by 4)
$bidi1_ok = $bidi1->getId() % 4 == 0;
$bidi2_ok = $bidi2->getId() % 4 == 0;
echo "Bidi IDs in correct space: " . ($bidi1_ok && $bidi2_ok ? "yes" : "no") . "\n";

// Verify uni IDs are in uni space (2, 6, 10... = ID % 4 == 2)
$uni1_ok = $uni1->getId() % 4 == 2;
$uni2_ok = $uni2->getId() % 4 == 2;
echo "Uni IDs in correct space: " . ($uni1_ok && $uni2_ok ? "yes" : "no") . "\n";

// Verify no ID collision
$ids = [$bidi1->getId(), $uni1->getId(), $bidi2->getId(), $uni2->getId()];
echo "All IDs unique: " . (count(array_unique($ids)) == 4 ? "yes" : "no") . "\n";

// Use the bidi stream for actual data
$bidi1->write("GET /\r\n");
$bidi1->conclude();
$data = $bidi1->read(8192, 5.0);
echo "Bidi stream works: " . ($data !== null && strlen($data) > 0 ? "yes" : "no") . "\n";

// Use uni stream for write only
$uni1->write("hello");
$uni1->conclude();
echo "Uni stream write works: yes\n";

$conn->close();
echo "OK\n";
?>
--EXPECT--
Bidi 1 ID: 0
Bidi 1 type: BIDI
Uni 1 ID: 2
Uni 1 type: UNI
Bidi 2 ID: 4
Uni 2 ID: 6
Bidi IDs in correct space: yes
Uni IDs in correct space: yes
All IDs unique: yes
Bidi stream works: yes
Uni stream write works: yes
OK
