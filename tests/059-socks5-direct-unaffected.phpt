--TEST--
Direct QUIC connection unaffected by SOCKS5 code paths
--EXTENSIONS--
quic
--FILE--
<?php

// Direct connection (no socks5_proxy) should work identically to before
$conn = quic_connect("www.cloudflare.com", 443, [
    "alpn" => ["h3"],
    "peer_name" => "www.cloudflare.com",
    "timeout" => 10,
    "verify_peer" => true,
]);
echo "Direct connected: " . ($conn->isConnected() ? "yes" : "no") . "\n";
echo "Direct ALPN: " . $conn->getAlpn() . "\n";

$stats = $conn->getStats();
echo "Stats available: " . (is_array($stats) ? "yes" : "no") . "\n";

$conn->close();
echo "Direct closed: " . ($conn->isConnected() ? "still connected" : "disconnected") . "\n";

echo "OK\n";
?>
--EXPECT--
Direct connected: yes
Direct ALPN: h3
Stats available: yes
Direct closed: disconnected
OK
