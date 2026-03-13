--TEST--
openStream() must validate stream type parameter (enum safety)
--DESCRIPTION--
openStream() accepts a type parameter that maps to SSL_STREAM_TYPE_BIDI or
SSL_STREAM_FLAG_UNI. Invalid values could be passed to SSL_new_stream(),
potentially triggering undefined behavior in OpenSSL. The extension must
reject invalid stream types with a ValueError.
--EXTENSIONS--
quic
--FILE--
<?php

$conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);

// Valid: BIDI (default)
$s = $conn->openStream();
echo "Default (BIDI): type=" . $s->getType() . "\n";
$s->conclude();

// Valid: explicit BIDI
$s = $conn->openStream(QUIC_STREAM_BIDI);
echo "Explicit BIDI: type=" . $s->getType() . "\n";
$s->conclude();

// Valid: UNI
$s = $conn->openStream(QUIC_STREAM_UNI);
echo "UNI: type=" . $s->getType() . "\n";
$s->conclude();

// Invalid: type 0
try {
    $s = $conn->openStream(0);
    echo "Type 0: accepted (got type=" . $s->getType() . ")\n";
    $s->conclude();
} catch (\Throwable $e) {
    echo "Type 0: rejected - " . $e->getMessage() . "\n";
}

// Invalid: type 2
try {
    $s = $conn->openStream(2);
    echo "Type 2: accepted\n";
    $s->conclude();
} catch (\Throwable $e) {
    echo "Type 2: rejected - " . $e->getMessage() . "\n";
}

// Invalid: type -1
try {
    $s = $conn->openStream(-1);
    echo "Type -1: accepted (BUG)\n";
} catch (\Throwable $e) {
    echo "Type -1: rejected\n";
}

// Invalid: type PHP_INT_MAX
try {
    $s = $conn->openStream(PHP_INT_MAX);
    echo "Type PHP_INT_MAX: accepted (BUG)\n";
} catch (\Throwable $e) {
    echo "Type PHP_INT_MAX: rejected\n";
}

// Invalid: type 999
try {
    $s = $conn->openStream(999);
    echo "Type 999: accepted (BUG)\n";
} catch (\Throwable $e) {
    echo "Type 999: rejected\n";
}

$conn->close();
echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECTF--
Default (BIDI): type=%d
Explicit BIDI: type=%d
UNI: type=%d
Type 0: %s
Type 2: rejected - %s
Type -1: rejected
Type PHP_INT_MAX: rejected
Type 999: rejected
No crash: yes
OK
