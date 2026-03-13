--TEST--
QuicConnection statistics
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

$stats = $conn->getStats();
echo "Has bytes_sent: " . (array_key_exists("bytes_sent", $stats) ? "yes" : "no") . "\n";
echo "Has bytes_received: " . (array_key_exists("bytes_received", $stats) ? "yes" : "no") . "\n";
echo "Has streams_opened: " . (array_key_exists("streams_opened", $stats) ? "yes" : "no") . "\n";
echo "Initial streams: " . $stats["streams_opened"] . "\n";

// Open a stream and do some I/O
$s = $conn->openStream();
$s->write("GET /\r\n");
$s->conclude();
$s->read(8192, 5.0);

$stats2 = $conn->getStats();
echo "Streams after open: " . $stats2["streams_opened"] . "\n";
echo "Bytes sent > 0: " . ($stats2["bytes_sent"] > 0 ? "yes" : "no") . "\n";
echo "Bytes received > 0: " . ($stats2["bytes_received"] > 0 ? "yes" : "no") . "\n";

$conn->close();
echo "OK\n";
?>
--EXPECT--
Has bytes_sent: yes
Has bytes_received: yes
Has streams_opened: yes
Initial streams: 0
Streams after open: 1
Bytes sent > 0: yes
Bytes received > 0: yes
OK
