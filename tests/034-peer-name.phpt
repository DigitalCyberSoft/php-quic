--TEST--
QuicConnection peer_name option overrides SNI
--EXTENSIONS--
quic
--FILE--
<?php

// peer_name overrides host for SNI - connect using peer_name matching the server
$conn = new QuicConnection("quic.aiortc.org", 443, [
    "alpn" => ["hq-interop"],
    "peer_name" => "quic.aiortc.org",
]);
$conn->connect();
echo "peer_name matching host: " . ($conn->isConnected() ? "connected" : "failed") . "\n";
$conn->close();

// peer_name that doesn't match the certificate should fail with verify_peer enabled
try {
    $conn2 = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "peer_name" => "wrong.example.com",
        "verify_peer" => true,
    ]);
    $conn2->connect();
    echo "FAIL: should have thrown with mismatched peer_name\n";
    $conn2->close();
} catch (RuntimeException $e) {
    echo "Mismatched peer_name: caught RuntimeException\n";
}

// peer_name mismatch should succeed when verify_peer is disabled
$conn3 = new QuicConnection("quic.aiortc.org", 443, [
    "alpn" => ["hq-interop"],
    "peer_name" => "wrong.example.com",
    "verify_peer" => false,
]);
$conn3->connect();
echo "Mismatched peer_name + no verify: " . ($conn3->isConnected() ? "connected" : "failed") . "\n";
$conn3->close();

echo "OK\n";
?>
--EXPECT--
peer_name matching host: connected
Mismatched peer_name: caught RuntimeException
Mismatched peer_name + no verify: connected
OK
