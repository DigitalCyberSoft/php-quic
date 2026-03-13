--TEST--
QuicConnection TLS 1.3 ciphersuites option
--EXTENSIONS--
quic
--FILE--
<?php

// Connect with a specific TLS 1.3 ciphersuite
$conn = new QuicConnection("quic.aiortc.org", 443, [
    "alpn" => ["hq-interop"],
    "ciphersuites" => "TLS_AES_256_GCM_SHA384",
]);
$conn->connect();
echo "Single ciphersuite: " . ($conn->isConnected() ? "connected" : "failed") . "\n";
$conn->close();

// Connect with multiple TLS 1.3 ciphersuites
$conn2 = new QuicConnection("quic.aiortc.org", 443, [
    "alpn" => ["hq-interop"],
    "ciphersuites" => "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
]);
$conn2->connect();
echo "Multiple ciphersuites: " . ($conn2->isConnected() ? "connected" : "failed") . "\n";
$conn2->close();

// Invalid ciphersuite string should throw during construction
try {
    new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "ciphersuites" => "COMPLETELY_INVALID_CIPHER",
    ]);
    echo "FAIL: should have thrown\n";
} catch (RuntimeException $e) {
    echo "Invalid ciphersuite: caught RuntimeException\n";
}

echo "OK\n";
?>
--EXPECT--
Single ciphersuite: connected
Multiple ciphersuites: connected
Invalid ciphersuite: caught RuntimeException
OK
