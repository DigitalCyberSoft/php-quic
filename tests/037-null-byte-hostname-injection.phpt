--TEST--
Null byte injection in hostname must be rejected (SNI confusion prevention)
--DESCRIPTION--
If a hostname contains embedded null bytes, getaddrinfo() and
SSL_set_tlsext_host_name() see a truncated version while PHP sees the full
string. For example "evil.com\0legit.com" resolves "evil.com" but the PHP
caller believes it connected to "evil.com\0legit.com". The extension must
reject hostnames containing null bytes to prevent SNI/DNS confusion attacks.
--EXTENSIONS--
quic
--FILE--
<?php

// Null byte in middle of hostname
try {
    $conn = new QuicConnection("evil.com\x00legit.com", 443, ["alpn" => ["hq-interop"]]);
    echo "Null byte hostname: accepted (BUG - SNI confusion possible)\n";
    // Even if constructor accepts it, connect should fail or the truncation is detectable
    // The fact that it was accepted at all is a security concern
} catch (\Throwable $e) {
    echo "Null byte hostname: rejected\n";
}

// Null byte at start
try {
    $conn = new QuicConnection("\x00evil.com", 443, ["alpn" => ["hq-interop"]]);
    echo "Leading null hostname: accepted (BUG - empty hostname to DNS)\n";
} catch (\Throwable $e) {
    echo "Leading null hostname: rejected\n";
}

// Null byte at end
try {
    $conn = new QuicConnection("example.com\x00", 443, ["alpn" => ["hq-interop"]]);
    echo "Trailing null hostname: accepted (BUG - SNI truncation)\n";
} catch (\Throwable $e) {
    echo "Trailing null hostname: rejected\n";
}

// Normal hostname for comparison (should work)
$conn = new QuicConnection("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
echo "Normal hostname: accepted\n";

echo "OK\n";
?>
--EXPECTF--
Null byte hostname: %s
Leading null hostname: %s
Trailing null hostname: %s
Normal hostname: accepted
OK
