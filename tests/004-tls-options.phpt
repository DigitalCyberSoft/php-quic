--TEST--
QuicConnection TLS options
--EXTENSIONS--
quic
--FILE--
<?php

// Test with verify_peer disabled
$conn = new QuicConnection("quic.aiortc.org", 443, [
    "alpn" => ["hq-interop"],
    "verify_peer" => false,
]);
$conn->connect();
echo "Connected with verify_peer=false: " . ($conn->isConnected() ? "yes" : "no") . "\n";

$cert = $conn->getPeerCertificate();
echo "Has certificate: " . ($cert !== null ? "yes" : "no") . "\n";
echo "Certificate is PEM: " . (str_contains($cert, "BEGIN CERTIFICATE") ? "yes" : "no") . "\n";

$conn->close();

// Test with verify_peer enabled (default)
$conn2 = new QuicConnection("quic.aiortc.org", 443, [
    "alpn" => ["hq-interop"],
]);
$conn2->connect();
echo "Connected with verify_peer=true: " . ($conn2->isConnected() ? "yes" : "no") . "\n";
$conn2->close();

echo "OK\n";
?>
--EXPECT--
Connected with verify_peer=false: yes
Has certificate: yes
Certificate is PEM: yes
Connected with verify_peer=true: yes
OK
