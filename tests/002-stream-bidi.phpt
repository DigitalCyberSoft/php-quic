--TEST--
QuicStream bidirectional stream operations
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

// Open a bidi stream
$s = $conn->openStream(QUIC_STREAM_BIDI);
echo "Type: " . $s->getType() . "\n";
echo "QUIC_STREAM_BIDI: " . QUIC_STREAM_BIDI . "\n";
echo "Is bidi: " . ($s->getType() == QUIC_STREAM_BIDI ? "yes" : "no") . "\n";

echo "Readable: " . ($s->isReadable() ? "yes" : "no") . "\n";
echo "Writable: " . ($s->isWritable() ? "yes" : "no") . "\n";

$written = $s->write("GET /\r\n");
echo "Written: " . $written . " bytes\n";

$s->conclude();

$data = $s->read(8192, 5.0);
echo "Read data: " . (strlen($data) > 0 ? "yes" : "no") . "\n";

$conn->close();
echo "OK\n";
?>
--EXPECT--
Type: 3
QUIC_STREAM_BIDI: 3
Is bidi: yes
Readable: yes
Writable: yes
Written: 7 bytes
Read data: yes
OK
