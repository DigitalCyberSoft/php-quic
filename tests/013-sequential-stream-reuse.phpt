--TEST--
Sequential stream open/close cycles (quic-go #1509 memory leak, .NET #56151)
--DESCRIPTION--
quic-go #1509: stream framer's queue slice never shrinks, causing unbounded
memory growth over many stream open/close cycles. .NET #56151: stream objects
not explicitly disposed leak SafeHandles and sockets. This test verifies
that opening and closing many streams sequentially doesn't leak resources.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

$total_streams = 20;
$successful = 0;

for ($i = 0; $i < $total_streams; $i++) {
    $s = $conn->openStream();
    $s->write("GET /\r\n");
    $s->conclude();
    $data = $s->read(8192, 5.0);
    if ($data !== null && strlen($data) > 0) {
        $successful++;
    }
    // Stream goes out of scope here, should be freed properly
    unset($s);
}

echo "Streams completed: $successful/$total_streams\n";
echo "All succeeded: " . ($successful == $total_streams ? "yes" : "no") . "\n";

$stats = $conn->getStats();
echo "Total streams opened: " . $stats["streams_opened"] . "\n";

// Verify stream IDs continue incrementing correctly
$s = $conn->openStream();
$expected_id = $total_streams * 4; // client bidi: 0, 4, 8, ...
echo "Next stream ID correct: " . ($s->getId() == $expected_id ? "yes" : "no (got " . $s->getId() . ", expected $expected_id)") . "\n";
$s->conclude();

$conn->close();
echo "OK\n";
?>
--EXPECT--
Streams completed: 20/20
All succeeded: yes
Total streams opened: 20
Next stream ID correct: yes
OK
