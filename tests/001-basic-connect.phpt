--TEST--
QuicConnection basic connect and stream
--EXTENSIONS--
quic
--FILE--
<?php

$conn = new QuicConnection("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
echo "Created connection\n";

echo "Connected before: " . ($conn->isConnected() ? "yes" : "no") . "\n";
$conn->connect();
echo "Connected after: " . ($conn->isConnected() ? "yes" : "no") . "\n";

$alpn = $conn->getAlpn();
echo "ALPN: " . $alpn . "\n";

$stream = $conn->openStream();
echo "Stream ID: " . $stream->getId() . "\n";
echo "Stream type: " . $stream->getType() . "\n";

$stream->write("GET /\r\n");
$stream->conclude();

$response = $stream->read(8192, 5.0);
echo "Got response: " . (strlen($response) > 0 ? "yes" : "no") . "\n";
echo "Response contains HTML: " . (str_contains($response, "<html") || str_contains($response, "<!DOCTYPE") ? "yes" : "no") . "\n";

$conn->close();
echo "Closed: " . ($conn->isConnected() ? "still connected" : "disconnected") . "\n";

echo "OK\n";
?>
--EXPECT--
Created connection
Connected before: no
Connected after: yes
ALPN: hq-interop
Stream ID: 0
Stream type: 3
Got response: yes
Response contains HTML: yes
Closed: disconnected
OK
