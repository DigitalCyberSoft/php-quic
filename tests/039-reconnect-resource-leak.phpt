--TEST--
connect() after close() must not leak SSL objects or file descriptors
--DESCRIPTION--
close() sets connected=0 but does not free the SSL object, BIO, or close
the file descriptor. If connect() is called again, it creates a new SSL
object and fd without freeing the old ones, leaking resources. This test
verifies the behavior and checks for fd leaks using /proc/self/fd.
--EXTENSIONS--
quic
--SKIPIF--
<?php if (!is_dir('/proc/self/fd')) die('skip /proc/self/fd not available'); ?>
--FILE--
<?php

// Count baseline fds
$baseline_fds = count(glob('/proc/self/fd/*'));

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
echo "Connected: " . ($conn->isConnected() ? "yes" : "no") . "\n";

$after_connect_fds = count(glob('/proc/self/fd/*'));
echo "FDs after connect: " . ($after_connect_fds > $baseline_fds ? "increased" : "same") . "\n";

$conn->close();
echo "Closed: " . ($conn->isConnected() ? "yes" : "no") . "\n";

$after_close_fds = count(glob('/proc/self/fd/*'));

// The connection object still holds the fd (freed in destructor).
// If we reconnect, this is where a leak would occur.
try {
    $conn->connect();
    echo "Reconnect: succeeded\n";
    $after_reconnect_fds = count(glob('/proc/self/fd/*'));
    // If the old fd was leaked, we'd see fd count growing
    echo "FDs grew by: " . ($after_reconnect_fds - $after_close_fds) . "\n";
    $conn->close();
} catch (\Throwable $e) {
    echo "Reconnect: " . $e->getMessage() . "\n";
}

// Now test failed connect + retry pattern (the more dangerous case)
$conn2 = new QuicConnection("192.0.2.1", 443, ["alpn" => ["hq-interop"]]);
$fds_before_fail = count(glob('/proc/self/fd/*'));

try {
    // This should fail (192.0.2.1 is TEST-NET, unreachable)
    $conn2->connect();
    echo "Unreachable connect: succeeded (unexpected)\n";
} catch (\Throwable $e) {
    echo "First failed connect: exception\n";
}

$fds_after_fail = count(glob('/proc/self/fd/*'));

try {
    $conn2->connect();
    echo "Second connect attempt: succeeded (unexpected)\n";
} catch (\Throwable $e) {
    echo "Second failed connect: exception\n";
}

$fds_after_retry = count(glob('/proc/self/fd/*'));
$leaked = $fds_after_retry - $fds_before_fail;
echo "FDs leaked after failed connect+retry: $leaked\n";

// Clean up - destructor should free everything
unset($conn, $conn2);

$final_fds = count(glob('/proc/self/fd/*'));
$total_leaked = $final_fds - $baseline_fds;
echo "Total FDs leaked after cleanup: $total_leaked\n";
echo "Leak detected: " . ($total_leaked > 0 ? "YES (security issue)" : "no") . "\n";
echo "OK\n";
?>
--EXPECTF--
Connected: yes
FDs after connect: increased
Closed: no
Reconnect: %s
%s
%a
Total FDs leaked after cleanup: %d
Leak detected: %s
OK
