--TEST--
Multiple concurrent streams (QUIC interop runner, flow control deadlock quic-go #1545)
--DESCRIPTION--
Tests opening multiple streams simultaneously on a single connection. quic-go
issue #1545 found flow control deadlock when multiple streams compete for
connection-level send window. The interop runner "transfer" test requires
concurrent stream multiplexing to work correctly.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

$streams = [];
$requests = ["/", "/", "/", "/", "/"];

// Open 5 concurrent streams
for ($i = 0; $i < count($requests); $i++) {
    $s = $conn->openStream();
    $s->write("GET " . $requests[$i] . "\r\n");
    $s->conclude();
    $streams[] = $s;
    echo "Stream $i opened, ID=" . $s->getId() . "\n";
}

// Verify stream IDs follow QUIC spec: client-initiated bidi = 0, 4, 8, 12, 16...
$ids = array_map(fn($s) => $s->getId(), $streams);
$correct_spacing = true;
for ($i = 1; $i < count($ids); $i++) {
    if ($ids[$i] - $ids[$i-1] != 4) {
        $correct_spacing = false;
        break;
    }
}
echo "Stream IDs spaced by 4: " . ($correct_spacing ? "yes" : "no") . "\n";

// Read responses from all streams
$responses = 0;
foreach ($streams as $i => $s) {
    $data = $s->read(8192, 5.0);
    if ($data !== null && strlen($data) > 0) {
        $responses++;
    }
}
echo "Responses received: $responses/" . count($streams) . "\n";

// All streams should have been tracked
$stats = $conn->getStats();
echo "Streams opened in stats: " . $stats["streams_opened"] . "\n";
echo "Bytes sent > 0: " . ($stats["bytes_sent"] > 0 ? "yes" : "no") . "\n";
echo "Bytes received > 0: " . ($stats["bytes_received"] > 0 ? "yes" : "no") . "\n";

$conn->close();
echo "OK\n";
?>
--EXPECT--
Stream 0 opened, ID=0
Stream 1 opened, ID=4
Stream 2 opened, ID=8
Stream 3 opened, ID=12
Stream 4 opened, ID=16
Stream IDs spaced by 4: yes
Responses received: 5/5
Streams opened in stats: 5
Bytes sent > 0: yes
Bytes received > 0: yes
OK
