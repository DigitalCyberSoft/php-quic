--TEST--
Half-closed stream: read after local FIN (quic-go #596, RFC 9000 s3)
--DESCRIPTION--
A bidirectional stream can be half-closed: client sends FIN while server
continues sending. quic-go issue #596 found that implementations failed to
properly track both send and receive halves independently.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

// Open stream, send request, close our send side
$s = $conn->openStream();
$s->write("GET /\r\n");
$s->conclude();

// After conclude, write state should not be OK
$writeState = $s->getWriteState();
echo "Write state after conclude: " . ($writeState != QUIC_STREAM_STATE_OK ? "not OK" : "still OK") . "\n";

// But read state should still be OK - server hasn't sent FIN yet
$readState = $s->getReadState();
echo "Read state after local conclude: " . ($readState == QUIC_STREAM_STATE_OK ? "OK" : $readState) . "\n";

// Should still be able to read server's response (half-closed)
$data = $s->read(8192, 5.0);
echo "Read after local FIN: " . ($data !== null && strlen($data) > 0 ? "got data" : "no data") . "\n";

// After reading the full response, read state should transition to FINISHED
$remaining = $s->read(8192, 1.0);
$finalReadState = $s->getReadState();
echo "Final read state: " . ($finalReadState == QUIC_STREAM_STATE_FINISHED || $remaining === null ? "finished" : $finalReadState) . "\n";

$conn->close();
echo "OK\n";
?>
--EXPECT--
Write state after conclude: not OK
Read state after local conclude: OK
Read after local FIN: got data
Final read state: finished
OK
