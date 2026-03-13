--TEST--
getPeerCertificate() must not leak memory on repeated calls
--DESCRIPTION--
getPeerCertificate() calls zend_string_init("OpenSSLCertificate", ...) on each
invocation but never frees the created zend_string. This causes a memory leak
on every call. This test calls it repeatedly and verifies no crash occurs.
The actual memory leak would be caught by PHP's leak detector in debug builds.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

// Call getPeerCertificate() many times to trigger the leak
$results = [];
for ($i = 0; $i < 100; $i++) {
    $cert = $conn->getPeerCertificate();
    if ($i == 0) {
        echo "First call returned: " . (is_string($cert) ? "PEM string" : (is_null($cert) ? "null" : gettype($cert))) . "\n";
        if (is_string($cert)) {
            echo "Contains BEGIN CERTIFICATE: " . (str_contains($cert, "BEGIN CERTIFICATE") ? "yes" : "no") . "\n";
        }
    }
    // Keep first and last to verify consistency
    if ($i == 0 || $i == 99) {
        $results[$i] = $cert;
    }
}

// Verify results are consistent
echo "Results consistent: " . ($results[0] === $results[99] ? "yes" : "no") . "\n";
echo "100 calls completed: yes\n";

$conn->close();

// Call after close - should return null or cached data, not crash
$cert_after = $conn->getPeerCertificate();
echo "After close: " . (is_string($cert_after) || is_null($cert_after) ? "safe" : "unexpected") . "\n";

echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECTF--
First call returned: PEM string
Contains BEGIN CERTIFICATE: yes
Results consistent: yes
100 calls completed: yes
After close: safe
No crash: yes
OK
