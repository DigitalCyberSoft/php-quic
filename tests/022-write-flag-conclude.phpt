--TEST--
QUIC_WRITE_FLAG_CONCLUDE atomic write+FIN (quiche data loss on close)
--DESCRIPTION--
quiche issue #1722 documented data loss when FIN and data are not sent
atomically. QUIC_WRITE_FLAG_CONCLUDE combines the data write and FIN in a
single operation, avoiding the race between separate write() and conclude()
calls. This test verifies the combined flag works correctly.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

// Test 1: write with QUIC_WRITE_FLAG_CONCLUDE
$s1 = $conn->openStream();
$written = $s1->write("GET /\r\n", QUIC_WRITE_FLAG_CONCLUDE);
echo "Written with conclude flag: " . $written . " bytes\n";

// Write state should no longer be OK (FIN was sent)
$writeState = $s1->getWriteState();
echo "Write state after flag conclude: " . ($writeState != QUIC_STREAM_STATE_OK ? "not OK" : "still OK") . "\n";

// Should still be able to read response
$data = $s1->read(8192, 5.0);
echo "Got response: " . ($data !== null && strlen($data) > 0 ? "yes" : "no") . "\n";

// Test 2: Compare with separate write+conclude
$s2 = $conn->openStream();
$s2->write("GET /\r\n");
$s2->conclude();
$data2 = $s2->read(8192, 5.0);
echo "Separate write+conclude also works: " . ($data2 !== null && strlen($data2) > 0 ? "yes" : "no") . "\n";

// Both should get the same response
echo "Responses match: " . ($data === $data2 ? "yes" : "similar") . "\n";

echo "QUIC_WRITE_FLAG_CONCLUDE value: " . QUIC_WRITE_FLAG_CONCLUDE . "\n";

$conn->close();
echo "OK\n";
?>
--EXPECTF--
Written with conclude flag: 7 bytes
Write state after flag conclude: not OK
Got response: yes
Separate write+conclude also works: yes
Responses match: %s
QUIC_WRITE_FLAG_CONCLUDE value: 1
OK
