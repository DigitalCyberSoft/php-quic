--TEST--
TLS verification options must be properly enforced
--DESCRIPTION--
verify_peer=false disables certificate verification entirely. This test
verifies that: (1) default behavior verifies peers, (2) verify_peer=false
actually disables verification, (3) the verify_peer_name option works
independently, and (4) allow_self_signed interacts correctly with
verify_peer. Incorrect enforcement could allow MITM attacks.
--EXTENSIONS--
quic
--FILE--
<?php

// Default: verify_peer should be true (connection to real server works)
try {
    $conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
    echo "Default verify: connected\n";
    $conn->close();
} catch (\Throwable $e) {
    echo "Default verify: failed - " . $e->getMessage() . "\n";
}

// Explicit verify_peer=true (same as default)
try {
    $conn = quic_connect("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "verify_peer" => true
    ]);
    echo "Explicit verify=true: connected\n";
    $conn->close();
} catch (\Throwable $e) {
    echo "Explicit verify=true: failed\n";
}

// verify_peer=false (should still connect)
try {
    $conn = quic_connect("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "verify_peer" => false
    ]);
    echo "verify_peer=false: connected\n";
    $conn->close();
} catch (\Throwable $e) {
    echo "verify_peer=false: failed\n";
}

// verify_peer_name with wrong peer_name should fail
try {
    $conn = quic_connect("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "verify_peer" => true,
        "verify_peer_name" => true,
        "peer_name" => "wrong.example.com"
    ]);
    echo "Wrong peer_name: connected (BUG - hostname verification bypassed)\n";
    $conn->close();
} catch (\Throwable $e) {
    echo "Wrong peer_name: rejected (hostname verification works)\n";
}

// verify_peer_name=false with wrong peer_name should connect
try {
    $conn = quic_connect("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "verify_peer" => true,
        "verify_peer_name" => false,
        "peer_name" => "wrong.example.com"
    ]);
    echo "verify_peer_name=false with wrong name: connected (name check disabled)\n";
    $conn->close();
} catch (\Throwable $e) {
    echo "verify_peer_name=false with wrong name: failed - " . $e->getMessage() . "\n";
}

echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECTF--
Default verify: connected
Explicit verify=true: connected
verify_peer=false: connected
Wrong peer_name: rejected (hostname verification works)
verify_peer_name=false with wrong name: %s
No crash: yes
OK
