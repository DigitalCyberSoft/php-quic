--TEST--
QuicStream unidirectional stream
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

// Open a uni stream
$s = $conn->openStream(QUIC_STREAM_UNI);
echo "QUIC_STREAM_UNI: " . QUIC_STREAM_UNI . "\n";
echo "Stream ID: " . $s->getId() . "\n";

// Uni stream should be writable but not readable
echo "Writable: " . ($s->isWritable() ? "yes" : "no") . "\n";

$written = $s->write("hello");
echo "Written: " . $written . " bytes\n";

$s->conclude();
echo "Concluded\n";

$conn->close();
echo "OK\n";
?>
--EXPECT--
QUIC_STREAM_UNI: 1
Stream ID: 2
Writable: yes
Written: 5 bytes
Concluded
OK
