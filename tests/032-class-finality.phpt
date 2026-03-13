--TEST--
Classes are final and deny dynamic properties (security hardening)
--DESCRIPTION--
QuicConnection and QuicStream are marked final with NO_DYNAMIC_PROPERTIES to
prevent subclassing attacks and property injection. This mirrors security
patterns from MsQuic and quiche where subclassing internal types led to
unexpected state corruption.
--EXTENSIONS--
quic
--FILE--
<?php

// QuicConnection is final
$rc = new ReflectionClass("QuicConnection");
echo "QuicConnection is final: " . ($rc->isFinal() ? "yes" : "no") . "\n";

// QuicStream is final
$rs = new ReflectionClass("QuicStream");
echo "QuicStream is final: " . ($rs->isFinal() ? "yes" : "no") . "\n";

// QuicStream constructor is private
$ctor = $rs->getConstructor();
echo "QuicStream constructor is private: " . ($ctor && $ctor->isPrivate() ? "yes" : "no") . "\n";

// Cannot add dynamic properties to QuicConnection
$conn = new QuicConnection("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
try {
    $conn->dynamicProp = "test";
    echo "BUG: dynamic property should be rejected\n";
} catch (Error $e) {
    echo "Dynamic property rejected: yes\n";
}

// Cannot instantiate QuicStream directly
try {
    $s = new QuicStream();
    echo "BUG: direct QuicStream instantiation should fail\n";
} catch (Error $e) {
    echo "Direct QuicStream instantiation blocked: yes\n";
}

// Verify the classes have the expected methods
$connMethods = array_map(fn($m) => $m->getName(), $rc->getMethods());
echo "QuicConnection has connect: " . (in_array("connect", $connMethods) ? "yes" : "no") . "\n";
echo "QuicConnection has openStream: " . (in_array("openStream", $connMethods) ? "yes" : "no") . "\n";
echo "QuicConnection has close: " . (in_array("close", $connMethods) ? "yes" : "no") . "\n";

$streamMethods = array_map(fn($m) => $m->getName(), $rs->getMethods());
echo "QuicStream has read: " . (in_array("read", $streamMethods) ? "yes" : "no") . "\n";
echo "QuicStream has write: " . (in_array("write", $streamMethods) ? "yes" : "no") . "\n";
echo "QuicStream has conclude: " . (in_array("conclude", $streamMethods) ? "yes" : "no") . "\n";

echo "OK\n";
?>
--EXPECT--
QuicConnection is final: yes
QuicStream is final: yes
QuicStream constructor is private: yes
Dynamic property rejected: yes
Direct QuicStream instantiation blocked: yes
QuicConnection has connect: yes
QuicConnection has openStream: yes
QuicConnection has close: yes
QuicStream has read: yes
QuicStream has write: yes
QuicStream has conclude: yes
OK
