--TEST--
Error codes at boundary values must not cause crashes (integer safety)
--DESCRIPTION--
close() and reset() accept error codes as zend_long but pass them to OpenSSL
as uint64_t. Negative values, zero, PHP_INT_MAX, and PHP_INT_MIN must all be
handled without crashes or undefined behavior from the cast.
--EXTENSIONS--
quic
--FILE--
<?php

// Test close() with various error codes

// Normal close (error code 0)
$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$result = $conn->close(0, "normal");
echo "close(0): " . ($result ? "true" : "false") . "\n";

// Close with large error code
$conn2 = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$result = $conn2->close(PHP_INT_MAX, "max error code");
echo "close(PHP_INT_MAX): " . ($result ? "true" : "false") . "\n";

// Close with negative error code (cast to uint64_t wraps)
$conn3 = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$result = $conn3->close(-1, "negative error code");
echo "close(-1): " . ($result ? "true" : "false") . "\n";

// Close with PHP_INT_MIN
$conn4 = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$result = $conn4->close(PHP_INT_MIN, "min error code");
echo "close(PHP_INT_MIN): " . ($result ? "true" : "false") . "\n";

// Test reset() with various error codes
$conn5 = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$s = $conn5->openStream();

// Normal reset
$result = $s->reset(0);
echo "reset(0): " . ($result ? "true" : "false") . "\n";

// Reset with PHP_INT_MAX
$s2 = $conn5->openStream();
$result = $s2->reset(PHP_INT_MAX);
echo "reset(PHP_INT_MAX): " . ($result ? "true" : "false") . "\n";

// Reset with negative
$s3 = $conn5->openStream();
$result = $s3->reset(-1);
echo "reset(-1): " . ($result ? "true" : "false") . "\n";

// Close with very long reason string
$conn6 = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$long_reason = str_repeat("R", 65536);
$result = $conn6->close(1, $long_reason);
echo "close with 64KB reason: " . ($result ? "true" : "false") . "\n";

// Close with empty reason
$conn7 = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$result = $conn7->close(1, "");
echo "close with empty reason: " . ($result ? "true" : "false") . "\n";

echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECTF--
close(0): true
close(PHP_INT_MAX): %s
close(-1): %s
close(PHP_INT_MIN): %s
reset(0): %s
reset(PHP_INT_MAX): %s
reset(-1): %s
close with 64KB reason: %s
close with empty reason: %s
No crash: yes
OK
