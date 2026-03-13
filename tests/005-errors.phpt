--TEST--
QuicConnection and QuicStream error handling
--EXTENSIONS--
quic
--FILE--
<?php

// Empty host
try {
    new QuicConnection("", 443);
    echo "FAIL: should have thrown\n";
} catch (ValueError $e) {
    echo "Empty host: " . $e->getMessage() . "\n";
}

// Invalid port (0)
try {
    new QuicConnection("test", 0);
    echo "FAIL: should have thrown\n";
} catch (ValueError $e) {
    echo "Port 0: " . $e->getMessage() . "\n";
}

// Invalid port (too high)
try {
    new QuicConnection("test", 99999);
    echo "FAIL: should have thrown\n";
} catch (ValueError $e) {
    echo "Port 99999: " . $e->getMessage() . "\n";
}

// Bad hostname resolution
try {
    $c = new QuicConnection("nonexistent.invalid.test", 443);
    $c->connect();
    echo "FAIL: should have thrown\n";
} catch (RuntimeException $e) {
    echo "Bad host: caught RuntimeException\n";
}

// Double connect
$c = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
try {
    $c->connect();
    echo "FAIL: should have thrown\n";
} catch (RuntimeException $e) {
    echo "Double connect: " . $e->getMessage() . "\n";
}
$c->close();

// Close unconnected
$c2 = new QuicConnection("quic.aiortc.org", 443);
echo "Close unconnected: " . ($c2->close() ? "true" : "false") . "\n";

// openStream when not connected
try {
    $c3 = new QuicConnection("quic.aiortc.org", 443);
    $c3->openStream();
    echo "FAIL: should have thrown\n";
} catch (RuntimeException $e) {
    echo "Stream without connect: " . $e->getMessage() . "\n";
}

// Invalid stream type
$c4 = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
try {
    $c4->openStream(999);
    echo "FAIL: should have thrown\n";
} catch (ValueError $e) {
    echo "Bad stream type: " . $e->getMessage() . "\n";
}
$c4->close();

echo "OK\n";
?>
--EXPECT--
Empty host: Host must not be empty
Port 0: Port must be between 1 and 65535
Port 99999: Port must be between 1 and 65535
Bad host: caught RuntimeException
Double connect: Already connected
Close unconnected: false
Stream without connect: Not connected
Bad stream type: Stream type must be QUIC_STREAM_BIDI or QUIC_STREAM_UNI
OK
