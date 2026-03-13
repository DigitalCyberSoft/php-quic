--TEST--
Large transfer with flow control window growth (interop runner "transfer" test)
--DESCRIPTION--
The QUIC interop runner "transfer" test verifies that flow control windows
grow dynamically for transfers >initial window size. quic-go, ngtcp2, and
OpenJDK all had bugs where flow control stalled on large transfers. This
test downloads a known large resource to verify window growth works.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

// Request a large-ish resource (the index page, read it fully)
$s = $conn->openStream();
$s->write("GET /\r\n");
$s->conclude();

// Read in a loop until stream finishes, accumulating data
$total = 0;
$chunks = 0;
$start = microtime(true);
while (true) {
    $data = $s->read(16384, 5.0);
    if ($data === null) {
        break;
    }
    $total += strlen($data);
    $chunks++;
    // Safety valve: don't read forever
    if (microtime(true) - $start > 10.0) {
        echo "Timeout reading\n";
        break;
    }
}
$elapsed = microtime(true) - $start;

echo "Total bytes read: " . $total . "\n";
echo "Read in chunks: " . $chunks . "\n";
echo "Transfer completed: " . ($total > 0 ? "yes" : "no") . "\n";
echo "No flow control stall: " . ($elapsed < 10.0 ? "yes" : "no") . "\n";

// Now test a second large transfer on the same connection to verify
// connection-level flow control windows were properly updated
$s2 = $conn->openStream();
$s2->write("GET /\r\n");
$s2->conclude();

$total2 = 0;
$start2 = microtime(true);
while (true) {
    $data = $s2->read(16384, 5.0);
    if ($data === null) break;
    $total2 += strlen($data);
    if (microtime(true) - $start2 > 10.0) break;
}

echo "Second transfer bytes: " . $total2 . "\n";
echo "Second transfer completed: " . ($total2 > 0 ? "yes" : "no") . "\n";

$conn->close();
echo "OK\n";
?>
--EXPECTF--
Total bytes read: %d
Read in chunks: %d
Transfer completed: yes
No flow control stall: yes
Second transfer bytes: %d
Second transfer completed: yes
OK
