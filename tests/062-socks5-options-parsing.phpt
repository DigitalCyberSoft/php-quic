--TEST--
SOCKS5 option parsing: socks5_proxy, socks5_username, socks5_password
--EXTENSIONS--
quic
--FILE--
<?php

// socks5_proxy with empty string should be ignored (direct connection)
$conn = quic_connect("www.cloudflare.com", 443, [
    "alpn" => ["h3"],
    "peer_name" => "www.cloudflare.com",
    "timeout" => 10,
    "verify_peer" => true,
    "socks5_proxy" => "",
]);
echo "Empty proxy: " . ($conn->isConnected() ? "connected direct" : "failed") . "\n";
$conn->close();

// socks5_proxy format validation - missing port
try {
    $conn = new QuicConnection("www.cloudflare.com", 443, [
        "socks5_proxy" => "127.0.0.1",
    ]);
    $conn->connect();
    echo "FAIL: no port should throw\n";
} catch (RuntimeException $e) {
    echo "No port: error caught\n";
}

// socks5_proxy format validation - with colon but no port number
try {
    $conn = new QuicConnection("www.cloudflare.com", 443, [
        "socks5_proxy" => "127.0.0.1:",
    ]);
    $conn->connect();
    echo "FAIL: empty port should throw\n";
} catch (RuntimeException $e) {
    echo "Empty port: error caught\n";
}

// socks5_username without socks5_password should work (password can be empty)
$conn = new QuicConnection("www.cloudflare.com", 443, [
    "alpn" => ["h3"],
    "socks5_proxy" => "127.0.0.1:19999",
    "socks5_username" => "user",
]);
echo "Username only: object created\n";

// socks5_password without socks5_username should be ignored
$conn = new QuicConnection("www.cloudflare.com", 443, [
    "alpn" => ["h3"],
    "socks5_proxy" => "127.0.0.1:19999",
    "socks5_password" => "pass",
]);
echo "Password only: object created\n";

echo "OK\n";
?>
--EXPECT--
Empty proxy: connected direct
No port: error caught
Empty port: error caught
Username only: object created
Password only: object created
OK
