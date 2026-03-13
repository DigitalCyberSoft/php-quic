--TEST--
Stream operations must check for null SSL pointer (use-after-free prevention)
--DESCRIPTION--
After a stream's parent connection is destroyed, the stream_ssl pointer may
become invalid. All stream methods must check for null stream_ssl before
dereferencing. This test exercises every stream method after the stream is
in a degraded state to verify no null pointer dereference occurs.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$s = $conn->openStream();
$s->write("GET /\r\n");
$s->conclude();
$s->read(8192, 5.0);

// Close connection - stream becomes degraded
$conn->close();

// Test every stream method - none should crash

// getReadState
try {
    $state = $s->getReadState();
    echo "getReadState: " . (is_int($state) ? "int ($state)" : "unexpected") . "\n";
} catch (\Throwable $e) {
    echo "getReadState: exception\n";
}

// getWriteState
try {
    $state = $s->getWriteState();
    echo "getWriteState: " . (is_int($state) ? "int ($state)" : "unexpected") . "\n";
} catch (\Throwable $e) {
    echo "getWriteState: exception\n";
}

// getId
try {
    $id = $s->getId();
    echo "getId: " . (is_int($id) ? "int ($id)" : "unexpected") . "\n";
} catch (\Throwable $e) {
    echo "getId: exception\n";
}

// getType
try {
    $type = $s->getType();
    echo "getType: " . (is_int($type) ? "int ($type)" : "unexpected") . "\n";
} catch (\Throwable $e) {
    echo "getType: exception\n";
}

// isReadable
try {
    $r = $s->isReadable();
    echo "isReadable: " . var_export($r, true) . "\n";
} catch (\Throwable $e) {
    echo "isReadable: exception\n";
}

// isWritable
try {
    $w = $s->isWritable();
    echo "isWritable: " . var_export($w, true) . "\n";
} catch (\Throwable $e) {
    echo "isWritable: exception\n";
}

// write
try {
    $s->write("test");
    echo "write: succeeded (unexpected after conn close)\n";
} catch (\Throwable $e) {
    echo "write: exception\n";
}

// read
try {
    $data = $s->read(8192, 0.1);
    echo "read: " . ($data === null ? "null" : "data") . "\n";
} catch (\Throwable $e) {
    echo "read: exception\n";
}

// conclude
try {
    $s->conclude();
    echo "conclude: returned\n";
} catch (\Throwable $e) {
    echo "conclude: exception\n";
}

// reset
try {
    $s->reset();
    echo "reset: returned\n";
} catch (\Throwable $e) {
    echo "reset: exception\n";
}

echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECTF--
getReadState: int (%d)
getWriteState: int (%d)
getId: int (%d)
getType: int (%d)
isReadable: %s
isWritable: %s
write: exception
read: %s
conclude: %s
reset: %s
No crash: yes
OK
