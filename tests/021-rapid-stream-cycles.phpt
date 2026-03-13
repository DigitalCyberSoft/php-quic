--TEST--
Rapid stream open/close stress test (stream ID management, .NET #32079)
--DESCRIPTION--
.NET runtime issue #32079: opening streams up to MAX_STREAMS and not properly
waiting for updates. quic-go #1509: stream queue never shrinks. This test
rapidly opens and closes streams to stress test ID management and resource
cleanup. Verifies no resource exhaustion or ID space issues.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

$opened = 0;
$errors = 0;
$target = 50;

for ($i = 0; $i < $target; $i++) {
    try {
        $s = $conn->openStream();
        $s->write("GET /\r\n");
        $s->conclude();
        // Don't wait for response - just close immediately
        unset($s);
        $opened++;
    } catch (RuntimeException $e) {
        $errors++;
        // If we hit MAX_STREAMS, that's expected behavior, not a bug
        break;
    }
}

echo "Streams opened: " . $opened . "\n";
echo "Errors: " . $errors . "\n";
echo "Connection alive: " . ($conn->isConnected() ? "yes" : "no") . "\n";

// Verify we can still do a full request/response after rapid cycling
$s = $conn->openStream();
$s->write("GET /\r\n");
$s->conclude();
$data = $s->read(8192, 5.0);
echo "Post-stress stream works: " . ($data !== null && strlen($data) > 0 ? "yes" : "no") . "\n";

$stats = $conn->getStats();
echo "Total streams tracked: " . $stats["streams_opened"] . "\n";

$conn->close();
echo "OK\n";
?>
--EXPECTF--
Streams opened: %d
Errors: %d
Connection alive: yes
Post-stress stream works: yes
Total streams tracked: %d
OK
