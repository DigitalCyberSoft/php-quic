--TEST--
Stream GC reference counting prevents premature connection free (.NET #56151)
--DESCRIPTION--
.NET runtime issue #56151: stream finalization without explicit dispose leaks
SafeHandles. The php-quic extension uses GC_ADDREF/OBJ_RELEASE to prevent the
connection from being freed while streams still reference it. This test verifies
that unsetting the connection variable while streams exist doesn't cause
use-after-free.
--EXTENSIONS--
quic
--FILE--
<?php

// Create connection and streams
$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$s1 = $conn->openStream();
$s1->write("GET /\r\n");
$s1->conclude();

$s2 = $conn->openStream();
$s2->write("GET /\r\n");
$s2->conclude();

// Unset the connection variable - but streams still hold a reference
unset($conn);
echo "Connection variable unset\n";

// Streams should still work because they hold GC references to the connection
$data1 = $s1->read(8192, 5.0);
echo "Stream 1 read after conn unset: " . ($data1 !== null && strlen($data1) > 0 ? "yes" : "no") . "\n";

$data2 = $s2->read(8192, 5.0);
echo "Stream 2 read after conn unset: " . ($data2 !== null && strlen($data2) > 0 ? "yes" : "no") . "\n";

// Stream state should still be queryable
echo "Stream 1 ID: " . $s1->getId() . "\n";
echo "Stream 2 ID: " . $s2->getId() . "\n";

// Cleanup happens when streams go out of scope
unset($s1);
echo "Stream 1 freed\n";
unset($s2);
echo "Stream 2 freed\n";

echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECT--
Connection variable unset
Stream 1 read after conn unset: yes
Stream 2 read after conn unset: yes
Stream 1 ID: 0
Stream 2 ID: 4
Stream 1 freed
Stream 2 freed
No crash: yes
OK
