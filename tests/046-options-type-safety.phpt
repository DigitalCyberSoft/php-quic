--TEST--
Constructor options must handle wrong types safely (type confusion prevention)
--DESCRIPTION--
The constructor reads options from an associative array. If values have
unexpected types (integer instead of string for cafile, array for verify_peer,
etc.), the extension must handle this safely without crashes or type confusion.
--EXTENSIONS--
quic
--FILE--
<?php

// ALPN as string instead of array
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, ["alpn" => "h3"]);
    echo "ALPN as string: accepted (ignored)\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "ALPN as string: rejected\n";
}

// ALPN as integer
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, ["alpn" => 42]);
    echo "ALPN as integer: accepted (ignored)\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "ALPN as integer: rejected\n";
}

// ALPN as nested arrays
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, ["alpn" => [["nested"]]]);
    echo "ALPN nested array: accepted (BUG)\n";
} catch (\Throwable $e) {
    echo "ALPN nested array: rejected\n";
}

// verify_peer as string
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "verify_peer" => "not_a_bool"
    ]);
    echo "verify_peer as string: " . ($conn !== null ? "accepted" : "null") . "\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "verify_peer as string: rejected\n";
}

// cafile as integer (should be ignored or cause type error)
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "cafile" => 12345
    ]);
    echo "cafile as integer: accepted (ignored type check)\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "cafile as integer: rejected\n";
}

// cafile as non-existent path
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "cafile" => "/nonexistent/path/to/ca.pem"
    ]);
    echo "cafile non-existent: accepted (BUG)\n";
} catch (\Throwable $e) {
    echo "cafile non-existent: rejected\n";
}

// ciphersuites as empty string
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "ciphersuites" => ""
    ]);
    echo "Empty ciphersuites: accepted\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "Empty ciphersuites: rejected\n";
}

// ciphersuites as invalid value
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "ciphersuites" => "COMPLETELY_INVALID_CIPHER"
    ]);
    echo "Invalid ciphersuites: accepted (BUG)\n";
} catch (\Throwable $e) {
    echo "Invalid ciphersuites: rejected\n";
}

// Unknown option keys (should be silently ignored)
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "unknown_option" => "value",
        "another_fake" => true
    ]);
    echo "Unknown options: silently ignored\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "Unknown options: rejected\n";
}

// Empty options array (valid)
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, []);
    echo "Empty options: accepted\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "Empty options: rejected\n";
}

echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECTF--
ALPN as string: accepted (ignored)
ALPN as integer: accepted (ignored)
ALPN nested array: rejected
verify_peer as string: accepted
cafile as integer: accepted (ignored type check)
cafile non-existent: rejected
Empty ciphersuites: %s
Invalid ciphersuites: rejected
Unknown options: silently ignored
Empty options: accepted
No crash: yes
OK
