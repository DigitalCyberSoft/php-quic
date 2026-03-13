--TEST--
Failed connection cleanup - no resource leak (CVE-2025-54939 pattern, .NET #56151)
--DESCRIPTION--
CVE-2025-54939 (LSQUIC): pre-handshake memory exhaustion from failed connections.
.NET #56151: failed connections leak SafeHandles. This test creates many failed
connections and verifies resources are properly released. File descriptors are
the most common leak vector.
--EXTENSIONS--
quic
--FILE--
<?php

// Get baseline file descriptor count
$fd_before = count(glob("/proc/self/fd/*"));

// Create 20 connections that will fail (bad host)
$failures = 0;
for ($i = 0; $i < 20; $i++) {
    try {
        $c = new QuicConnection("nonexistent-host-" . $i . ".invalid.test", 443, [
            "alpn" => ["hq-interop"]
        ]);
        $c->connect();
        echo "BUG: should not connect to invalid host\n";
    } catch (RuntimeException $e) {
        $failures++;
    }
    // Object goes out of scope, resources should be freed
}

echo "Failed connections: $failures\n";
echo "All failed: " . ($failures == 20 ? "yes" : "no") . "\n";

// Check for file descriptor leaks
$fd_after = count(glob("/proc/self/fd/*"));
$fd_leaked = $fd_after - $fd_before;
echo "FD leak: " . ($fd_leaked <= 2 ? "none" : "$fd_leaked leaked") . "\n";

// Verify a good connection still works after all the failures
$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
echo "Good connection after failures: " . ($conn->isConnected() ? "yes" : "no") . "\n";
$conn->close();

echo "OK\n";
?>
--EXPECT--
Failed connections: 20
All failed: yes
FD leak: none
Good connection after failures: yes
OK
