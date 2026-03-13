--TEST--
Double conclude must not crash (observed across multiple implementations)
--DESCRIPTION--
Calling SSL_stream_conclude() twice on the same stream is a common edge case.
Some implementations crash, others silently succeed, others return error.
The important thing is no crash and no connection corruption.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

$s = $conn->openStream();
$s->write("GET /\r\n");

// First conclude should succeed
$first = $s->conclude();
echo "First conclude: " . ($first ? "true" : "false") . "\n";

// Second conclude - should not crash
$threw = false;
try {
    $second = $s->conclude();
    echo "Second conclude: " . ($second ? "true" : "false") . "\n";
} catch (Throwable $e) {
    $threw = true;
    echo "Second conclude threw: " . get_class($e) . "\n";
}
echo "No crash after double conclude: yes\n";

// Stream should still be readable
$data = $s->read(8192, 5.0);
echo "Read after double conclude: " . ($data !== null && strlen($data) > 0 ? "got data" : "no data") . "\n";

// Connection should be healthy
echo "Connection alive: " . ($conn->isConnected() ? "yes" : "no") . "\n";

$conn->close();
echo "OK\n";
?>
--EXPECTF--
First conclude: true
%ANo crash after double conclude: yes
Read after double conclude: got data
Connection alive: yes
OK
