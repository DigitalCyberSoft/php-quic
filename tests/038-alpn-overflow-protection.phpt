--TEST--
ALPN buffer allocation must not overflow with many entries
--DESCRIPTION--
quic_build_alpn() uses unsigned int to track total ALPN wire format length.
With enough entries, this could overflow, causing a small emalloc followed by
a heap buffer overflow in the second pass. The extension must either limit
the number of ALPN entries or use a size type that cannot overflow.
This test verifies that excessively large ALPN arrays are handled safely.
--EXTENSIONS--
quic
--FILE--
<?php

// Test with reasonable number of ALPN protocols (should work)
$alpn = [];
for ($i = 0; $i < 10; $i++) {
    $alpn[] = "proto-$i";
}
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, ["alpn" => $alpn]);
    echo "10 ALPN protocols: accepted\n";
} catch (\Throwable $e) {
    echo "10 ALPN protocols: rejected - " . $e->getMessage() . "\n";
}

// Test with large number of ALPN protocols (stress test)
$alpn = [];
for ($i = 0; $i < 1000; $i++) {
    $alpn[] = str_repeat("x", 255); // max length per ALPN entry
}
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, ["alpn" => $alpn]);
    echo "1000 x 255-byte ALPN: accepted (no crash)\n";
} catch (\Throwable $e) {
    echo "1000 x 255-byte ALPN: rejected - " . get_class($e) . "\n";
}

// Test with empty ALPN strings (should be rejected)
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, ["alpn" => [""]]);
    echo "Empty ALPN: accepted (BUG)\n";
} catch (\Throwable $e) {
    echo "Empty ALPN: rejected\n";
}

// Test with non-string ALPN entries
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, ["alpn" => [123, 456]]);
    echo "Integer ALPN: accepted (BUG)\n";
} catch (\Throwable $e) {
    echo "Integer ALPN: rejected\n";
}

// Test with 256-byte ALPN string (exceeds max per entry)
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, ["alpn" => [str_repeat("a", 256)]]);
    echo "256-byte ALPN entry: accepted (BUG - exceeds wire format limit)\n";
} catch (\Throwable $e) {
    echo "256-byte ALPN entry: rejected\n";
}

echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECTF--
10 ALPN protocols: accepted
1000 x 255-byte ALPN: %s
Empty ALPN: rejected
Integer ALPN: rejected
256-byte ALPN entry: rejected
No crash: yes
OK
