--TEST--
GC safety with many streams and parent connection going out of scope
--DESCRIPTION--
When multiple streams hold references to a parent connection, the connection
must not be freed until ALL streams release their references. If the
GC_ADDREF/OBJ_RELEASE counting is wrong, premature free leads to
use-after-free. This test creates many streams, drops the connection
reference, and verifies all streams remain functional.
--EXTENSIONS--
quic
--FILE--
<?php

$streams = [];

// Create connection and open multiple streams
$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

for ($i = 0; $i < 5; $i++) {
    $s = $conn->openStream();
    $s->write("GET /\r\n");
    $s->conclude();
    $streams[] = $s;
}

echo "Streams created: " . count($streams) . "\n";

// Drop connection reference - streams should keep it alive
unset($conn);
echo "Connection variable unset\n";

// Force garbage collection
gc_collect_cycles();
echo "GC run completed\n";

// All streams should still be functional for state queries
$working = 0;
foreach ($streams as $i => $s) {
    try {
        $id = $s->getId();
        if (is_int($id)) {
            $working++;
        }
    } catch (\Throwable $e) {
        echo "Stream $i getId failed: " . $e->getMessage() . "\n";
    }
}
echo "Streams still working: $working/" . count($streams) . "\n";

// Read from streams (some may have data)
foreach ($streams as $i => $s) {
    try {
        $data = $s->read(8192, 2.0);
        echo "Stream $i read: " . ($data !== null ? "data" : "null") . "\n";
    } catch (\Throwable $e) {
        echo "Stream $i read: exception\n";
    }
}

// Release streams one by one
while (!empty($streams)) {
    array_pop($streams);
}
echo "All streams released\n";

// Another GC cycle - connection should now be freed
gc_collect_cycles();
echo "Final GC completed\n";

echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECTF--
Streams created: 5
Connection variable unset
GC run completed
Streams still working: 5/5
Stream 0 read: %s
Stream 1 read: %s
Stream 2 read: %s
Stream 3 read: %s
Stream 4 read: %s
All streams released
Final GC completed
No crash: yes
OK
