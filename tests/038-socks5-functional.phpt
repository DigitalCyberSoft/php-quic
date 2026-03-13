--TEST--
QuicConnection SOCKS5 proxy functional (TCP handshake + UDP relay)
--EXTENSIONS--
quic
--SKIPIF--
<?php
// Need a working SOCKS5 proxy with UDP ASSOCIATE support
// microsocks is commonly available on test systems
$out = shell_exec("which microsocks 2>/dev/null || which dante 2>/dev/null || which 3proxy 2>/dev/null");
if (!$out) die("skip no SOCKS5 proxy available (install microsocks)");
?>
--FILE--
<?php

// Start microsocks on a random port
$port = rand(30000, 39999);
$proc = proc_open(
    "microsocks -p $port",
    [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes
);
if (!$proc) {
    echo "FAIL: could not start microsocks\n";
    exit(1);
}
// Give it time to bind
usleep(200000);

// Verify proxy is listening
$sock = @stream_socket_client("tcp://127.0.0.1:$port", $errno, $errstr, 2);
if (!$sock) {
    echo "FAIL: proxy not listening\n";
    proc_terminate($proc);
    proc_close($proc);
    exit(1);
}
fclose($sock);

// Connect through the SOCKS5 proxy
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "verify_peer" => false,
        "socks5_proxy" => "127.0.0.1:$port",
    ]);
    $conn->connect();
    echo "SOCKS5 connect: " . ($conn->isConnected() ? "connected" : "failed") . "\n";

    // Verify we can actually transfer data through the proxy
    $stream = $conn->openStream();
    $stream->write("GET /\r\n");
    $stream->conclude();
    $response = $stream->read(8192, 5.0);
    echo "Got response: " . (strlen($response) > 0 ? "yes" : "no") . "\n";

    $conn->close();
    echo "Closed: " . ($conn->isConnected() ? "still connected" : "disconnected") . "\n";
} catch (RuntimeException $e) {
    echo "Exception: " . $e->getMessage() . "\n";
}

// Cleanup
proc_terminate($proc);
proc_close($proc);

echo "OK\n";
?>
--EXPECT--
SOCKS5 connect: connected
Got response: yes
Closed: disconnected
OK
