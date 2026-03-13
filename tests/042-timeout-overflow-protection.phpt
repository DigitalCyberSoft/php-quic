--TEST--
Extreme timeout values must not cause integer overflow or hang
--DESCRIPTION--
The read() timeout calculation converts a double to microseconds via
(long)(timeout * 1000000.0). For very large timeout values, this overflows
a long, potentially producing a negative timeout (which would be treated
as already expired) or wrapping to a small positive value. The extension
must handle extreme timeout values safely.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$s = $conn->openStream();
$s->write("GET /\r\n");
$s->conclude();

// Normal timeout should work
$data = $s->read(8192, 5.0);
echo "Normal timeout read: " . ($data !== null ? "ok" : "null") . "\n";

// Zero timeout - should return immediately
$s2 = $conn->openStream();
$s2->write("GET /\r\n");
$s2->conclude();
$start = microtime(true);
$data2 = $s2->read(8192, 0.0);
$elapsed = microtime(true) - $start;
echo "Zero timeout returned in < 1s: " . ($elapsed < 1.0 ? "yes" : "no ($elapsed s)") . "\n";

// Very small timeout
$s3 = $conn->openStream();
$s3->write("GET /\r\n");
$s3->conclude();
$data3 = $s3->read(8192, 0.001);
echo "1ms timeout: " . ($data3 === null ? "timed out" : "got data") . "\n";

// Negative timeout (should use blocking mode)
$s4 = $conn->openStream();
$s4->write("GET /\r\n");
$s4->conclude();
$data4 = $s4->read(8192, -1.0);
echo "Negative timeout (blocking): " . ($data4 !== null ? "ok" : "null") . "\n";

// Very large timeout - should not hang or overflow
// The test itself has a 30s timeout, so if this hangs it'll fail
$s5 = $conn->openStream();
$s5->write("GET /\r\n");
$s5->conclude();
try {
    $data5 = $s5->read(8192, 999999999.0);
    echo "Huge timeout: " . ($data5 !== null ? "got data (ok)" : "null") . "\n";
} catch (\Throwable $e) {
    echo "Huge timeout: exception - " . $e->getMessage() . "\n";
}

// NaN timeout
$s6 = $conn->openStream();
$s6->write("GET /\r\n");
$s6->conclude();
try {
    $data6 = $s6->read(8192, NAN);
    echo "NaN timeout: returned " . ($data6 === null ? "null" : "data") . "\n";
} catch (\Throwable $e) {
    echo "NaN timeout: exception\n";
}

// INF timeout
$s7 = $conn->openStream();
$s7->write("GET /\r\n");
$s7->conclude();
try {
    $data7 = $s7->read(8192, INF);
    echo "INF timeout: returned " . ($data7 === null ? "null" : "data") . "\n";
} catch (\Throwable $e) {
    echo "INF timeout: exception\n";
}

$conn->close();
echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECTF--
Normal timeout read: ok
Zero timeout returned in < 1s: yes
1ms timeout: %s
Negative timeout (blocking): ok
Huge timeout: %s
NaN timeout: %s
INF timeout: %s
No crash: yes
OK
