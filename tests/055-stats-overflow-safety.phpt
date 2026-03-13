--TEST--
Stats counters must not produce incorrect values (overflow safety)
--DESCRIPTION--
bytes_sent, bytes_received are uint64_t cast to zend_long for PHP. On
64-bit systems zend_long is int64_t, so values above INT64_MAX would appear
negative. streams_opened is uint32_t. This test verifies stats remain
consistent and non-negative through normal operations.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

// Initial stats should be zero or small
$stats = $conn->getStats();
echo "Initial bytes_sent type: " . gettype($stats["bytes_sent"]) . "\n";
echo "Initial bytes_received type: " . gettype($stats["bytes_received"]) . "\n";
echo "Initial streams_opened type: " . gettype($stats["streams_opened"]) . "\n";
echo "Initial bytes_sent >= 0: " . ($stats["bytes_sent"] >= 0 ? "yes" : "no (NEGATIVE!)") . "\n";
echo "Initial bytes_received >= 0: " . ($stats["bytes_received"] >= 0 ? "yes" : "no (NEGATIVE!)") . "\n";
echo "Initial streams_opened: " . $stats["streams_opened"] . "\n";

// Do some work
$s = $conn->openStream();
$s->write("GET /\r\n");
$s->conclude();
$data = $s->read(8192, 5.0);

$stats2 = $conn->getStats();
echo "After work bytes_sent > 0: " . ($stats2["bytes_sent"] > 0 ? "yes" : "no") . "\n";
echo "After work bytes_received > 0: " . ($stats2["bytes_received"] > 0 ? "yes" : "no") . "\n";
echo "After work streams_opened: " . $stats2["streams_opened"] . "\n";
echo "bytes_sent monotonic: " . ($stats2["bytes_sent"] >= $stats["bytes_sent"] ? "yes" : "no") . "\n";
echo "bytes_received monotonic: " . ($stats2["bytes_received"] >= $stats["bytes_received"] ? "yes" : "no") . "\n";

// Stats after close
$conn->close();
$stats3 = $conn->getStats();
echo "Stats after close: " . (is_array($stats3) ? "array" : "error") . "\n";
echo "bytes_sent preserved: " . ($stats3["bytes_sent"] == $stats2["bytes_sent"] ? "yes" : "no") . "\n";
echo "streams_opened preserved: " . ($stats3["streams_opened"] == $stats2["streams_opened"] ? "yes" : "no") . "\n";

// All values still non-negative
echo "All non-negative: " . (
    $stats3["bytes_sent"] >= 0 &&
    $stats3["bytes_received"] >= 0 &&
    $stats3["streams_opened"] >= 0 ? "yes" : "no"
) . "\n";

echo "OK\n";
?>
--EXPECT--
Initial bytes_sent type: integer
Initial bytes_received type: integer
Initial streams_opened type: integer
Initial bytes_sent >= 0: yes
Initial bytes_received >= 0: yes
Initial streams_opened: 0
After work bytes_sent > 0: yes
After work bytes_received > 0: yes
After work streams_opened: 1
bytes_sent monotonic: yes
bytes_received monotonic: yes
Stats after close: array
bytes_sent preserved: yes
streams_opened preserved: yes
All non-negative: yes
OK
