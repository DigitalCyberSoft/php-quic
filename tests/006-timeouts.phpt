--TEST--
QuicStream read timeout
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

// Open a stream but don't write anything - read should timeout
$s = $conn->openStream();

// Read with a very short timeout
$start = microtime(true);
$result = $s->read(8192, 0.5);
$elapsed = microtime(true) - $start;

echo "Read result: " . ($result === null ? "null" : "data") . "\n";
echo "Timeout worked: " . ($elapsed < 3.0 ? "yes" : "no") . "\n";

$conn->close();
echo "OK\n";
?>
--EXPECT--
Read result: null
Timeout worked: yes
OK
