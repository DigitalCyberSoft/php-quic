--TEST--
Port validation must reject out-of-range values (integer overflow prevention)
--DESCRIPTION--
Port is validated as 1-65535 in __construct but the parameter is zend_long
(64-bit). Values outside the range must be rejected cleanly. This also tests
boundary conditions that could cause issues with the sockaddr port field
(which is uint16_t in network byte order).
--EXTENSIONS--
quic
--FILE--
<?php

// Valid port boundaries
try {
    $conn = new QuicConnection("quic.aiortc.org", 1, ["alpn" => ["hq-interop"]]);
    echo "Port 1: accepted\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "Port 1: rejected - " . $e->getMessage() . "\n";
}

try {
    $conn = new QuicConnection("quic.aiortc.org", 65535, ["alpn" => ["hq-interop"]]);
    echo "Port 65535: accepted\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "Port 65535: rejected - " . $e->getMessage() . "\n";
}

// Invalid port: 0
try {
    $conn = new QuicConnection("quic.aiortc.org", 0, ["alpn" => ["hq-interop"]]);
    echo "Port 0: accepted (BUG)\n";
} catch (\Throwable $e) {
    echo "Port 0: rejected\n";
}

// Invalid port: negative
try {
    $conn = new QuicConnection("quic.aiortc.org", -1, ["alpn" => ["hq-interop"]]);
    echo "Port -1: accepted (BUG)\n";
} catch (\Throwable $e) {
    echo "Port -1: rejected\n";
}

// Invalid port: 65536
try {
    $conn = new QuicConnection("quic.aiortc.org", 65536, ["alpn" => ["hq-interop"]]);
    echo "Port 65536: accepted (BUG)\n";
} catch (\Throwable $e) {
    echo "Port 65536: rejected\n";
}

// Invalid port: large number that could overflow uint16_t
try {
    $conn = new QuicConnection("quic.aiortc.org", 131071, ["alpn" => ["hq-interop"]]);
    echo "Port 131071: accepted (BUG - wraps to 65535)\n";
} catch (\Throwable $e) {
    echo "Port 131071: rejected\n";
}

// Invalid port: PHP_INT_MAX
try {
    $conn = new QuicConnection("quic.aiortc.org", PHP_INT_MAX, ["alpn" => ["hq-interop"]]);
    echo "Port PHP_INT_MAX: accepted (BUG)\n";
} catch (\Throwable $e) {
    echo "Port PHP_INT_MAX: rejected\n";
}

// Invalid port: PHP_INT_MIN
try {
    $conn = new QuicConnection("quic.aiortc.org", PHP_INT_MIN, ["alpn" => ["hq-interop"]]);
    echo "Port PHP_INT_MIN: accepted (BUG)\n";
} catch (\Throwable $e) {
    echo "Port PHP_INT_MIN: rejected\n";
}

echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECT--
Port 1: accepted
Port 65535: accepted
Port 0: rejected
Port -1: rejected
Port 65536: rejected
Port 131071: rejected
Port PHP_INT_MAX: rejected
Port PHP_INT_MIN: rejected
No crash: yes
OK
