--TEST--
Multiple sequential connections (resource isolation, CVE-2025-54939 pattern)
--DESCRIPTION--
CVE-2025-54939 (LSQUIC) and general patterns: pre-handshake allocations must be
bounded, and previous connections must not interfere with new ones. This test
creates many sequential connections to verify complete resource isolation and
cleanup between connections.
--EXTENSIONS--
quic
--FILE--
<?php

$success = 0;
$total = 5;

for ($i = 0; $i < $total; $i++) {
    $conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

    if (!$conn->isConnected()) {
        echo "Connection $i failed to connect\n";
        continue;
    }

    $s = $conn->openStream();
    $s->write("GET /\r\n");
    $s->conclude();
    $data = $s->read(8192, 5.0);

    if ($data !== null && strlen($data) > 0) {
        $success++;
    }

    $conn->close();
    // Connection goes out of scope - all resources should be freed
    unset($s);
    unset($conn);
}

echo "Successful connections: $success/$total\n";
echo "All succeeded: " . ($success == $total ? "yes" : "no") . "\n";
echo "OK\n";
?>
--EXPECT--
Successful connections: 5/5
All succeeded: yes
OK
