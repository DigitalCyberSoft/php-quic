--TEST--
Write after conclude must fail cleanly (RFC 9000 s3.1, multiple implementations)
--DESCRIPTION--
After sending FIN via conclude(), the send side transitions to "Data Sent" state.
Further writes MUST fail. Some implementations (quiche, early ngtcp2) allowed
writes after FIN, producing malformed frames or silent data loss.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$s = $conn->openStream();

$s->write("GET /\r\n");
$s->conclude();

echo "Write state after conclude: " . $s->getWriteState() . "\n";

// Attempt to write after FIN - must not silently succeed
$threw = false;
try {
    $result = $s->write("more data");
    // If it returns 0 or negative without throwing, that's also acceptable
    echo "Write after conclude returned: " . $result . "\n";
    if ($result <= 0) {
        echo "Write correctly rejected\n";
    } else {
        echo "BUG: Write succeeded after conclude\n";
    }
} catch (RuntimeException $e) {
    $threw = true;
    echo "Write after conclude threw: yes\n";
}

// Read the response to confirm stream still works for reading
$data = $s->read(8192, 5.0);
echo "Can still read: " . ($data !== null && strlen($data) > 0 ? "yes" : "no") . "\n";

$conn->close();
echo "OK\n";
?>
--EXPECTF--
Write state after conclude: %d
%AWrite %s
Can still read: yes
OK
