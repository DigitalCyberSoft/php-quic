--TEST--
QuicConnection ALPN negotiation
--EXTENSIONS--
quic
--FILE--
<?php

// Connect with hq-interop ALPN
$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
echo "ALPN: " . $conn->getAlpn() . "\n";
$conn->close();

// ALPN should be null when not connected
$conn2 = new QuicConnection("quic.aiortc.org", 443);
echo "ALPN before connect: " . ($conn2->getAlpn() === null ? "null" : $conn2->getAlpn()) . "\n";

echo "OK\n";
?>
--EXPECT--
ALPN: hq-interop
ALPN before connect: null
OK
