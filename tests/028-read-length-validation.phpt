--TEST--
Read length boundary validation (buffer overflow prevention)
--DESCRIPTION--
Many QUIC implementations had buffer overflow vulnerabilities from inadequate
input validation on read lengths. CVE-2024-26190 (MsQuic) involved unbounded
memory allocation. This test verifies that the read length parameter is
properly validated at boundaries.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
$s = $conn->openStream();
$s->write("GET /\r\n");
$s->conclude();

// Test: read with length = 0 (must reject)
try {
    $s->read(0, 5.0);
    echo "BUG: read(0) should throw\n";
} catch (ValueError $e) {
    echo "read(0) rejected: yes\n";
}

// Test: read with negative length (must reject)
try {
    $s->read(-1, 5.0);
    echo "BUG: read(-1) should throw\n";
} catch (ValueError $e) {
    echo "read(-1) rejected: yes\n";
}

// Test: read with very large length (must reject, 16MB limit)
try {
    $s->read(16777217, 5.0);
    echo "BUG: read(16MB+1) should throw\n";
} catch (ValueError $e) {
    echo "read(16MB+1) rejected: yes\n";
}

// Test: read with max valid length (16MB) should be accepted
$data = $s->read(16777216, 5.0);
echo "read(16MB) accepted: " . ($data !== null ? "yes" : "null (stream ended)") . "\n";

// Test: read with length = 1 (minimum valid)
$s2 = $conn->openStream();
$s2->write("GET /\r\n");
$s2->conclude();
$data = $s2->read(1, 5.0);
echo "read(1) works: " . ($data !== null ? "yes, got " . strlen($data) . " byte(s)" : "null") . "\n";

$conn->close();
echo "OK\n";
?>
--EXPECTF--
read(0) rejected: yes
read(-1) rejected: yes
read(16MB+1) rejected: yes
read(16MB) accepted: %s
read(1) works: yes, got 1 byte(s)
OK
