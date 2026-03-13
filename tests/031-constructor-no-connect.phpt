--TEST--
Constructor must not trigger connection (OpenSSL PR #25069 false start)
--DESCRIPTION--
OpenSSL PR #25069 fixed a bug where certain SSL functions inadvertently
triggered QUIC connection establishment. The QuicConnection constructor must
only configure the context, not initiate a connection. This test verifies
that creating the object is side-effect-free.
--EXTENSIONS--
quic
--FILE--
<?php

// Constructor should not connect
$conn = new QuicConnection("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
echo "isConnected after construct: " . ($conn->isConnected() ? "yes" : "no") . "\n";

// ALPN should be null before connect
echo "ALPN before connect: " . ($conn->getAlpn() === null ? "null" : $conn->getAlpn()) . "\n";

// getPeerCertificate should be null before connect
echo "Cert before connect: " . ($conn->getPeerCertificate() === null ? "null" : "exists") . "\n";

// openStream should fail before connect
try {
    $conn->openStream();
    echo "BUG: openStream should fail before connect\n";
} catch (RuntimeException $e) {
    echo "openStream before connect: " . $e->getMessage() . "\n";
}

// Now connect and verify it works
$conn->connect();
echo "isConnected after connect: " . ($conn->isConnected() ? "yes" : "no") . "\n";
echo "ALPN after connect: " . $conn->getAlpn() . "\n";

$conn->close();
echo "OK\n";
?>
--EXPECT--
isConnected after construct: no
ALPN before connect: null
Cert before connect: null
openStream before connect: Not connected
isConnected after connect: yes
ALPN after connect: hq-interop
OK
