--TEST--
Zero-length write must not crash (ngtcp2 assertion error, MsQuic edge case)
--DESCRIPTION--
Writing zero bytes is valid in QUIC (can carry FIN bit). ngtcp2 had an assertion
error on zero-length DATAGRAM writes. Some implementations crash or produce
undefined behavior with empty writes.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$s = $conn->openStream();

// Zero-length write should not crash
$threw = false;
try {
    $result = $s->write("");
    echo "Empty write returned: " . var_export($result, true) . "\n";
} catch (Throwable $e) {
    $threw = true;
    echo "Empty write threw: " . get_class($e) . "\n";
}
echo "No crash after empty write: yes\n";

// Stream should still be usable after zero-length write
echo "Writable after empty write: " . ($s->isWritable() ? "yes" : "no") . "\n";

// Normal write should still work
$written = $s->write("GET /\r\n");
echo "Normal write after empty: " . ($written > 0 ? "yes" : "no") . "\n";

$s->conclude();
$data = $s->read(8192, 5.0);
echo "Got response: " . ($data !== null && strlen($data) > 0 ? "yes" : "no") . "\n";

$conn->close();
echo "OK\n";
?>
--EXPECTF--
%ANo crash after empty write: yes
Writable after empty write: yes
Normal write after empty: yes
Got response: yes
OK
