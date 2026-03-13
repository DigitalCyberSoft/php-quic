--TEST--
Stream operations after connection close must not crash (use-after-free prevention)
--DESCRIPTION--
Multiple implementations (MsQuic #4592, .NET #56151) had bugs where stream
objects held references to freed connection state, causing use-after-free.
The php-quic extension uses GC_ADDREF/OBJ_RELEASE to prevent this. This test
verifies that stream objects remain safe to use after their parent connection
is closed.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$s = $conn->openStream();
$s->write("GET /\r\n");
$s->conclude();

// Read some data before closing
$data = $s->read(8192, 5.0);
echo "Read before close: " . ($data !== null && strlen($data) > 0 ? "yes" : "no") . "\n";

// Close connection while stream object still exists
$conn->close();

// Stream state queries should not crash (even though connection is closed)
$readState = $s->getReadState();
echo "Read state type: " . (is_int($readState) ? "int" : "other") . "\n";

$writeState = $s->getWriteState();
echo "Write state type: " . (is_int($writeState) ? "int" : "other") . "\n";

$id = $s->getId();
echo "Stream ID accessible: " . (is_int($id) ? "yes" : "no") . "\n";

$type = $s->getType();
echo "Stream type accessible: " . (is_int($type) ? "yes" : "no") . "\n";

echo "isReadable: " . var_export($s->isReadable(), true) . "\n";
echo "isWritable: " . var_export($s->isWritable(), true) . "\n";

// Attempt write on stream after connection close
try {
    $s->write("more data");
    echo "Write after conn close: succeeded\n";
} catch (RuntimeException $e) {
    echo "Write after conn close: exception\n";
}

// Attempt read on stream after connection close
try {
    $readResult = $s->read(8192, 0.5);
    echo "Read after conn close: " . ($readResult === null ? "null" : "data") . "\n";
} catch (RuntimeException $e) {
    echo "Read after conn close: exception (protocol shutdown)\n";
}

echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECTF--
Read before close: yes
Read state type: int
Write state type: int
Stream ID accessible: yes
Stream type accessible: yes
isReadable: false
isWritable: false
Write after conn close: exception
Read after conn close: %s
No crash: yes
OK
