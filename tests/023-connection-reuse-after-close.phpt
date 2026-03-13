--TEST--
Connection operations after close must fail cleanly (MsQuic #4592 cleanup)
--DESCRIPTION--
MsQuic issue #4592: connection abort without proper cleanup leaks resources.
After close(), the connection object must refuse further operations cleanly
(no use-after-free, no crash, proper error messages). Verifies that all
methods behave correctly on a closed connection.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
echo "Connected: " . ($conn->isConnected() ? "yes" : "no") . "\n";

$conn->close();
echo "Closed: " . ($conn->isConnected() ? "yes" : "no") . "\n";

// openStream on closed connection
try {
    $conn->openStream();
    echo "BUG: openStream after close should fail\n";
} catch (RuntimeException $e) {
    echo "openStream after close: " . $e->getMessage() . "\n";
}

// Double close should not crash
$result = $conn->close();
echo "Double close returned: " . ($result ? "true" : "false") . "\n";

// getAlpn on closed connection - SSL object still exists (freed on destruct)
$alpn = $conn->getAlpn();
echo "ALPN after close: " . (is_string($alpn) || $alpn === null ? "accessible" : "error") . "\n";

// getStats should still work (returns cached data)
$stats = $conn->getStats();
echo "Stats after close: " . (is_array($stats) ? "array" : "error") . "\n";

// getPeerCertificate should not crash
$cert = $conn->getPeerCertificate();
echo "Cert after close: " . var_export($cert === null || is_string($cert), true) . "\n";

echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECT--
Connected: yes
Closed: no
openStream after close: Not connected
Double close returned: false
ALPN after close: accessible
Stats after close: array
Cert after close: true
No crash: yes
OK
