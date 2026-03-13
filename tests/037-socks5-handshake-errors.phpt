--TEST--
QuicConnection SOCKS5 proxy handshake errors
--EXTENSIONS--
quic
--FILE--
<?php

// Invalid socks5_proxy format (no port)
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "socks5_proxy" => "127.0.0.1",
    ]);
    $conn->connect();
    echo "FAIL: should have thrown\n";
} catch (RuntimeException $e) {
    echo "No port: " . $e->getMessage() . "\n";
}

// SOCKS5 proxy that doesn't exist (connection refused)
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "socks5_proxy" => "127.0.0.1:19999",
    ]);
    $conn->connect();
    echo "FAIL: should have thrown\n";
} catch (RuntimeException $e) {
    echo "Refused: caught RuntimeException\n";
}

// SOCKS5 proxy with unresolvable host
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "socks5_proxy" => "nonexistent.invalid.test:1080",
    ]);
    $conn->connect();
    echo "FAIL: should have thrown\n";
} catch (RuntimeException $e) {
    echo "Bad proxy host: caught RuntimeException\n";
}

// Without socks5_proxy, direct connection should still work
$conn = new QuicConnection("quic.aiortc.org", 443, [
    "alpn" => ["hq-interop"],
    "verify_peer" => false,
]);
$conn->connect();
echo "Direct (no proxy): " . ($conn->isConnected() ? "connected" : "failed") . "\n";
$conn->close();

echo "OK\n";
?>
--EXPECT--
No port: Invalid socks5_proxy format, expected host:port
Refused: caught RuntimeException
Bad proxy host: caught RuntimeException
Direct (no proxy): connected
OK
