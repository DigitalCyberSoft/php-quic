--TEST--
Stream state machine transitions (RFC 9000 s3, half-close tracking bugs)
--DESCRIPTION--
RFC 9000 Section 3 defines strict state machines for stream send/receive sides.
Multiple implementations (quic-go, quiche, msquic) had bugs in state tracking,
especially around FINISHED and RESET states. This test verifies the extension
correctly reports state transitions through the stream lifecycle.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

// Verify state constants are defined
echo "STATE_NONE: " . QUIC_STREAM_STATE_NONE . "\n";
echo "STATE_OK: " . QUIC_STREAM_STATE_OK . "\n";
echo "STATE_FINISHED: " . QUIC_STREAM_STATE_FINISHED . "\n";
echo "STATE_RESET_LOCAL: " . QUIC_STREAM_STATE_RESET_LOCAL . "\n";
echo "STATE_RESET_REMOTE: " . QUIC_STREAM_STATE_RESET_REMOTE . "\n";
echo "STATE_CONN_CLOSED: " . QUIC_STREAM_STATE_CONN_CLOSED . "\n";

// New stream: both sides should be OK
$s = $conn->openStream();
echo "New stream read state: " . ($s->getReadState() == QUIC_STREAM_STATE_OK ? "OK" : $s->getReadState()) . "\n";
echo "New stream write state: " . ($s->getWriteState() == QUIC_STREAM_STATE_OK ? "OK" : $s->getWriteState()) . "\n";
echo "isReadable: " . ($s->isReadable() ? "yes" : "no") . "\n";
echo "isWritable: " . ($s->isWritable() ? "yes" : "no") . "\n";

// After conclude: write side transitions, read side stays OK
$s->write("GET /\r\n");
$s->conclude();
$writeState = $s->getWriteState();
echo "After conclude write state != OK: " . ($writeState != QUIC_STREAM_STATE_OK ? "yes" : "no") . "\n";
echo "After conclude read state == OK: " . ($s->getReadState() == QUIC_STREAM_STATE_OK ? "yes" : "no") . "\n";

// Read until stream finishes
$data = $s->read(8192, 5.0);
while ($data !== null) {
    $data = $s->read(8192, 1.0);
}
$finalReadState = $s->getReadState();
echo "After full read, read state: " . ($finalReadState == QUIC_STREAM_STATE_FINISHED ? "FINISHED" : $finalReadState) . "\n";

// Test reset state
$s2 = $conn->openStream();
$s2->write("test");
$s2->reset(0);
echo "After reset write state: " . ($s2->getWriteState() == QUIC_STREAM_STATE_RESET_LOCAL ? "RESET_LOCAL" : $s2->getWriteState()) . "\n";

$conn->close();
echo "OK\n";
?>
--EXPECT--
STATE_NONE: 0
STATE_OK: 1
STATE_FINISHED: 3
STATE_RESET_LOCAL: 4
STATE_RESET_REMOTE: 5
STATE_CONN_CLOSED: 6
New stream read state: OK
New stream write state: OK
isReadable: yes
isWritable: yes
After conclude write state != OK: yes
After conclude read state == OK: yes
After full read, read state: FINISHED
After reset write state: RESET_LOCAL
OK
