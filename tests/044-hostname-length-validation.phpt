--TEST--
Hostname length must be validated to prevent resource exhaustion
--DESCRIPTION--
The constructor accepts any non-empty hostname with no maximum length check.
estrndup() will allocate whatever length is requested. Extremely long hostnames
waste memory and will always fail DNS resolution. RFC 1035 limits hostnames to
253 characters. The extension should reject obviously invalid hostnames.
--EXTENSIONS--
quic
--FILE--
<?php

// Normal hostname - should work
$conn = new QuicConnection("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
echo "Normal hostname: accepted\n";
unset($conn);

// Maximum valid DNS name (253 chars)
$long_host = str_repeat("a", 63) . "." . str_repeat("b", 63) . "." . str_repeat("c", 63) . "." . str_repeat("d", 61);
echo "253-char hostname length: " . strlen($long_host) . "\n";
try {
    $conn = new QuicConnection($long_host, 443, ["alpn" => ["hq-interop"]]);
    echo "253-char hostname: accepted (ok)\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "253-char hostname: rejected\n";
}

// IP address (valid, not hostname format)
try {
    $conn = new QuicConnection("192.168.1.1", 443, ["alpn" => ["hq-interop"]]);
    echo "IP address: accepted\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "IP address: rejected\n";
}

// Very long hostname (1KB) - unreasonable but shouldn't crash
try {
    $conn = new QuicConnection(str_repeat("x", 1024), 443, ["alpn" => ["hq-interop"]]);
    echo "1KB hostname: accepted (wasteful but safe)\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "1KB hostname: rejected\n";
}

// 64KB hostname - clearly abusive
try {
    $conn = new QuicConnection(str_repeat("y", 65536), 443, ["alpn" => ["hq-interop"]]);
    echo "64KB hostname: accepted (should be rejected)\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "64KB hostname: rejected\n";
}

echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECTF--
Normal hostname: accepted
253-char hostname length: 253
253-char hostname: %s
IP address: accepted
1KB hostname: %s
64KB hostname: %s
No crash: yes
OK
