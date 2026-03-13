--TEST--
Stream reset lifecycle (quiche 7eb57c4, OpenSSL SSL_stream_reset behavior)
--DESCRIPTION--
quiche commit 7eb57c4 fixed "properly handle incoming RESET_STREAM frames."
OpenSSL documents that after SSL_stream_reset(), subsequent calls succeed but
are ignored (first error code wins). This test verifies reset behavior and
that the connection remains healthy after stream resets.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

// Test 1: Reset a stream after writing
$s1 = $conn->openStream();
$s1->write("GET /\r\n");
$resetResult = $s1->reset(42);
echo "Reset returned: " . ($resetResult ? "true" : "false") . "\n";

// After reset, write state should be reset
$writeState = $s1->getWriteState();
echo "Write state after reset: " . ($writeState == QUIC_STREAM_STATE_RESET_LOCAL ? "RESET_LOCAL" : $writeState) . "\n";

// Test 2: Double reset with different error code (OpenSSL ignores second)
$s2 = $conn->openStream();
$s2->write("GET /\r\n");
$s2->reset(100);
$secondReset = $s2->reset(200);
echo "Second reset: " . ($secondReset ? "accepted" : "rejected") . "\n";
echo "No crash after double reset: yes\n";

// Test 3: Connection should still be healthy after stream resets
echo "Connection still alive: " . ($conn->isConnected() ? "yes" : "no") . "\n";

$s3 = $conn->openStream();
$s3->write("GET /\r\n");
$s3->conclude();
$data = $s3->read(8192, 5.0);
echo "New stream after resets works: " . ($data !== null && strlen($data) > 0 ? "yes" : "no") . "\n";

$conn->close();
echo "OK\n";
?>
--EXPECTF--
Reset returned: true
Write state after reset: RESET_LOCAL
Second reset: %s
No crash after double reset: yes
Connection still alive: yes
New stream after resets works: yes
OK
