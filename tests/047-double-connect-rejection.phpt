--TEST--
Double connect() must be rejected (state confusion prevention)
--DESCRIPTION--
Calling connect() on an already-connected object must throw an exception.
Without this check, a second SSL_new() would overwrite the existing SSL
pointer without freeing it, leaking memory and potentially corrupting state.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
echo "First connect: " . ($conn->isConnected() ? "yes" : "no") . "\n";

// Double connect must be rejected
try {
    $conn->connect();
    echo "Double connect: allowed (BUG - SSL leak)\n";
} catch (RuntimeException $e) {
    echo "Double connect: rejected - " . $e->getMessage() . "\n";
}

// Should still be connected after rejected double-connect
echo "Still connected: " . ($conn->isConnected() ? "yes" : "no") . "\n";

// Should still be functional
$s = $conn->openStream();
$s->write("GET /\r\n");
$s->conclude();
$data = $s->read(8192, 5.0);
echo "Stream works after rejected double-connect: " . ($data !== null ? "yes" : "no") . "\n";

$conn->close();
echo "OK\n";
?>
--EXPECT--
First connect: yes
Double connect: rejected - Already connected
Still connected: yes
Stream works after rejected double-connect: yes
OK
