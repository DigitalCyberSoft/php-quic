--TEST--
Connection close with open streams (quiche #1722, .NET #46542)
--DESCRIPTION--
quiche issue #1722: CONNECTION_CLOSE implicitly resets all streams. If sent
before stream data is acknowledged, the peer may never receive final data.
.NET #46542: graceful shutdown needs to wait for stream data ACKs. This test
verifies that closing a connection with open streams doesn't crash or leak.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

// Open multiple streams but don't read from all of them
$s1 = $conn->openStream();
$s1->write("GET /\r\n");
$s1->conclude();

$s2 = $conn->openStream();
$s2->write("GET /\r\n");
// Intentionally don't conclude s2

$s3 = $conn->openStream();
// Intentionally don't write to s3 at all

echo "Streams opened: 3\n";
echo "Stream 1 readable: " . ($s1->isReadable() ? "yes" : "no") . "\n";
echo "Stream 2 writable: " . ($s2->isWritable() ? "yes" : "no") . "\n";

// Close connection while streams are in various states
$result = $conn->close();
echo "Connection closed: " . ($result ? "yes" : "no") . "\n";
echo "Is connected: " . ($conn->isConnected() ? "yes" : "no") . "\n";

// After connection close, stream states should reflect closed connection
$s1ReadState = $s1->getReadState();
$s2WriteState = $s2->getWriteState();
echo "Stream 1 read state after close: " . ($s1ReadState == QUIC_STREAM_STATE_CONN_CLOSED || $s1ReadState == QUIC_STREAM_STATE_FINISHED || $s1ReadState == QUIC_STREAM_STATE_RESET_LOCAL ? "terminal" : $s1ReadState) . "\n";

echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECT--
Streams opened: 3
Stream 1 readable: yes
Stream 2 writable: yes
Connection closed: yes
Is connected: no
Stream 1 read state after close: terminal
No crash: yes
OK
