--TEST--
QuicConnection verify_peer_name option
--EXTENSIONS--
quic
--FILE--
<?php

// Default verify_peer_name=true should enforce hostname match
// This is tested implicitly via 010, but test the toggle here

// verify_peer_name=false should skip hostname check even with verify_peer=true
// Connect with a wrong peer_name but disable hostname verification
$conn = new QuicConnection("quic.aiortc.org", 443, [
    "alpn" => ["hq-interop"],
    "peer_name" => "wrong.example.com",
    "verify_peer" => true,
    "verify_peer_name" => false,
]);
$conn->connect();
echo "Wrong name + verify_peer_name=false: " . ($conn->isConnected() ? "connected" : "failed") . "\n";
$conn->close();

// verify_peer_name=true (explicit) with correct name should work
$conn2 = new QuicConnection("quic.aiortc.org", 443, [
    "alpn" => ["hq-interop"],
    "verify_peer" => true,
    "verify_peer_name" => true,
]);
$conn2->connect();
echo "Correct name + verify_peer_name=true: " . ($conn2->isConnected() ? "connected" : "failed") . "\n";
$conn2->close();

// verify_peer_name=true with wrong peer_name should fail
try {
    $conn3 = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "peer_name" => "wrong.example.com",
        "verify_peer" => true,
        "verify_peer_name" => true,
    ]);
    $conn3->connect();
    echo "FAIL: should have thrown\n";
    $conn3->close();
} catch (RuntimeException $e) {
    echo "Wrong name + verify_peer_name=true: caught RuntimeException\n";
}

echo "OK\n";
?>
--EXPECT--
Wrong name + verify_peer_name=false: connected
Correct name + verify_peer_name=true: connected
Wrong name + verify_peer_name=true: caught RuntimeException
OK
