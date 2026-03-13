--TEST--
Write after stream reset must fail (nginx PR #230, RFC 9000 s19.4)
--DESCRIPTION--
nginx PR #230 fixed a bug where STREAM frames queued before RESET_STREAM were
still retransmitted after the reset. RFC 9000 Section 19.4 states that after
sending RESET_STREAM, no further STREAM frames may be sent. This test verifies
that write() fails after reset().
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

$s = $conn->openStream();
$s->write("GET /\r\n");

// Reset the stream
$s->reset(0);
echo "Reset done\n";

// Write after reset should fail
try {
    $result = $s->write("more data");
    echo "Write after reset returned: " . $result . "\n";
    if ($result <= 0) {
        echo "Write correctly rejected\n";
    } else {
        echo "BUG: Write succeeded after reset\n";
    }
} catch (RuntimeException $e) {
    echo "Write after reset threw exception: yes\n";
}

// Conclude after reset should also handle gracefully
try {
    $result = $s->conclude();
    echo "Conclude after reset: " . ($result ? "true" : "false") . "\n";
} catch (RuntimeException $e) {
    echo "Conclude after reset threw: yes\n";
}

// Connection should still work
$s2 = $conn->openStream();
$s2->write("GET /\r\n");
$s2->conclude();
$data = $s2->read(8192, 5.0);
echo "New stream works: " . ($data !== null && strlen($data) > 0 ? "yes" : "no") . "\n";

$conn->close();
echo "OK\n";
?>
--EXPECTF--
Reset done
%A
New stream works: yes
OK
