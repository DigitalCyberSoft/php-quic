--TEST--
Connection close with application error code (RFC 9000 s10.2)
--DESCRIPTION--
RFC 9000 Section 10.2 defines CONNECTION_CLOSE with application error codes.
MsQuic issue #4166 found bugs in how error codes were propagated during close.
This test verifies that close() properly accepts and sends error codes and
reason strings.
--EXTENSIONS--
quic
--FILE--
<?php

// Test 1: Close with default (no error)
$conn1 = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$result1 = $conn1->close();
echo "Close with defaults: " . ($result1 ? "ok" : "fail") . "\n";

// Test 2: Close with explicit error code
$conn2 = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$result2 = $conn2->close(0);
echo "Close with code 0: " . ($result2 ? "ok" : "fail") . "\n";

// Test 3: Close with application error code and reason
$conn3 = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$result3 = $conn3->close(256, "application shutdown");
echo "Close with code+reason: " . ($result3 ? "ok" : "fail") . "\n";

// Test 4: Close with large error code
$conn4 = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$result4 = $conn4->close(0xFFFF, "max code test");
echo "Close with large code: " . ($result4 ? "ok" : "fail") . "\n";

echo "OK\n";
?>
--EXPECT--
Close with defaults: ok
Close with code 0: ok
Close with code+reason: ok
Close with large code: ok
OK
