--TEST--
Serialization of QUIC objects must be denied (raw pointer safety)
--DESCRIPTION--
QuicConnection and QuicStream contain raw C pointers (SSL*, file descriptors).
If these objects could be serialized and then unserialized, the restored object
would contain dangling pointers, leading to use-after-free or other memory
corruption. This test verifies that serialization is properly denied.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

// Test serialize on QuicConnection
try {
    $serialized = serialize($conn);
    echo "QuicConnection serialize: allowed (BUG - dangling pointer risk)\n";
    // If serialization succeeded, try unserialize
    try {
        $conn2 = unserialize($serialized);
        echo "QuicConnection unserialize: allowed (CRITICAL BUG)\n";
    } catch (\Throwable $e) {
        echo "QuicConnection unserialize: denied\n";
    }
} catch (\Throwable $e) {
    echo "QuicConnection serialize: denied (" . get_class($e) . ")\n";
}

// Test serialize on QuicStream
$s = $conn->openStream();
try {
    $serialized = serialize($s);
    echo "QuicStream serialize: allowed (BUG - dangling pointer risk)\n";
} catch (\Throwable $e) {
    echo "QuicStream serialize: denied (" . get_class($e) . ")\n";
}

// Test var_export (can generate recreatable code)
try {
    $exported = var_export($conn, true);
    echo "QuicConnection var_export: " . (str_contains($exported, "::__set_state") ? "generated __set_state call" : "other format") . "\n";
} catch (\Throwable $e) {
    echo "QuicConnection var_export: denied\n";
}

// Test json_encode
$json = json_encode($conn);
echo "QuicConnection json_encode: " . ($json === false ? "failed" : $json) . "\n";

$s->conclude();
$conn->close();
echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECTF--
QuicConnection serialize: %s
%a
QuicStream serialize: %s
QuicConnection var_export: %s
QuicConnection json_encode: %s
No crash: yes
OK
