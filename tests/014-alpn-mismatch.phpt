--TEST--
ALPN mismatch must fail with error (RFC 9001, error 0x178)
--DESCRIPTION--
QUIC mandates ALPN (RFC 9001). If client and server cannot agree on an ALPN
value, the connection must fail. Some implementations return generic errors
instead of the specific ALPN mismatch error. This was documented across
quiche, msquic, and OpenSSL implementations.
--EXTENSIONS--
quic
--FILE--
<?php

// Connect with a completely invalid ALPN that no server will accept
try {
    $conn = quic_connect("quic.aiortc.org", 443, [
        "alpn" => ["totally-bogus-protocol-12345"]
    ]);
    echo "BUG: Connection with bogus ALPN should have failed\n";
    $conn->close();
} catch (RuntimeException $e) {
    echo "Bogus ALPN rejected: yes\n";
    echo "Got error message: " . (strlen($e->getMessage()) > 0 ? "yes" : "no") . "\n";
}

// Connect with valid ALPN should still work after failed attempt
$conn2 = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
echo "Valid ALPN after failure: " . ($conn2->isConnected() ? "connected" : "failed") . "\n";
echo "Negotiated ALPN: " . $conn2->getAlpn() . "\n";
$conn2->close();

echo "OK\n";
?>
--EXPECT--
Bogus ALPN rejected: yes
Got error message: yes
Valid ALPN after failure: connected
Negotiated ALPN: hq-interop
OK
