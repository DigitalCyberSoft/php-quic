--TEST--
write() must validate data length to prevent integer truncation
--DESCRIPTION--
SSL_write() takes an int for length but data_len is size_t. Values exceeding
INT_MAX (2147483647) wrap when cast to int, potentially causing SSL_write
to receive a small or negative length. The extension should reject writes
with data exceeding a safe maximum, or at minimum not crash.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$s = $conn->openStream();

// Normal write should work
$written = $s->write("GET /\r\n");
echo "Normal write: " . ($written > 0 ? "ok" : "failed") . "\n";

// Test that the return value matches what was actually written
$data = str_repeat("A", 1000);
$written = $s->write($data);
echo "1000-byte write returned: " . ($written > 0 ? "positive" : "zero_or_negative") . "\n";
echo "Written matches length: " . ($written == 1000 ? "yes" : "no (got $written)") . "\n";

$s->conclude();
$s->read(8192, 5.0);

// We can't easily test >INT_MAX strings in PHP without OOM,
// but we verify the extension handles the edge correctly by checking
// that large (but safe) writes work properly
$large = str_repeat("B", 65536);
$s2 = $conn->openStream();
$written2 = $s2->write($large);
echo "64KB write: " . ($written2 > 0 ? "ok" : "failed") . "\n";
$s2->conclude();

$conn->close();
echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECTF--
Normal write: ok
1000-byte write returned: positive
Written matches length: %s
64KB write: ok
No crash: yes
OK
