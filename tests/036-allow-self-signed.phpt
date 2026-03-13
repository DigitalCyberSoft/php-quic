--TEST--
QuicConnection allow_self_signed option
--EXTENSIONS--
quic
--FILE--
<?php

// allow_self_signed with verify_peer should still connect to servers
// with valid certificates (the option only relaxes self-signed rejection)
$conn = new QuicConnection("quic.aiortc.org", 443, [
    "alpn" => ["hq-interop"],
    "verify_peer" => true,
    "allow_self_signed" => true,
]);
$conn->connect();
echo "Valid cert + allow_self_signed: " . ($conn->isConnected() ? "connected" : "failed") . "\n";
$conn->close();

// allow_self_signed=false (default) with valid cert should also work
$conn2 = new QuicConnection("quic.aiortc.org", 443, [
    "alpn" => ["hq-interop"],
    "verify_peer" => true,
    "allow_self_signed" => false,
]);
$conn2->connect();
echo "Valid cert + allow_self_signed=false: " . ($conn2->isConnected() ? "connected" : "failed") . "\n";
$conn2->close();

// allow_self_signed with verify_peer disabled is effectively a no-op
$conn3 = new QuicConnection("quic.aiortc.org", 443, [
    "alpn" => ["hq-interop"],
    "verify_peer" => false,
    "allow_self_signed" => true,
]);
$conn3->connect();
echo "No verify + allow_self_signed: " . ($conn3->isConnected() ? "connected" : "failed") . "\n";
$conn3->close();

echo "OK\n";
?>
--EXPECT--
Valid cert + allow_self_signed: connected
Valid cert + allow_self_signed=false: connected
No verify + allow_self_signed: connected
OK
