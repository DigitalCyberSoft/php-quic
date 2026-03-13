--TEST--
File path options must handle path traversal attempts safely
--DESCRIPTION--
The cafile, capath, local_cert, and local_pk options accept file system paths.
While PHP's security model trusts the script author, the extension should
handle non-existent paths, /dev/null, /proc paths, and directory traversal
without crashing or leaking file handles.
--EXTENSIONS--
quic
--FILE--
<?php

// Non-existent cafile (should fail cleanly)
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "cafile" => "/nonexistent/ca.pem"
    ]);
    echo "Non-existent cafile: accepted (BUG?)\n";
} catch (\Throwable $e) {
    echo "Non-existent cafile: rejected\n";
}

// /dev/null as cafile
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "cafile" => "/dev/null"
    ]);
    echo "/dev/null cafile: accepted\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "/dev/null cafile: rejected\n";
}

// Directory as cafile
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "cafile" => "/tmp"
    ]);
    echo "Directory as cafile: accepted\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "Directory as cafile: rejected\n";
}

// Non-existent capath
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "capath" => "/nonexistent/certs/"
    ]);
    echo "Non-existent capath: accepted\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "Non-existent capath: rejected\n";
}

// Non-existent local_cert
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "local_cert" => "/nonexistent/cert.pem"
    ]);
    echo "Non-existent local_cert: accepted (BUG?)\n";
} catch (\Throwable $e) {
    echo "Non-existent local_cert: rejected\n";
}

// Non-existent local_pk
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "local_pk" => "/nonexistent/key.pem"
    ]);
    echo "Non-existent local_pk: accepted (BUG?)\n";
} catch (\Throwable $e) {
    echo "Non-existent local_pk: rejected\n";
}

// Path with null bytes
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "cafile" => "/etc/ssl/certs/ca-certificates.crt\x00/etc/shadow"
    ]);
    echo "Null byte in cafile path: accepted (potential path truncation)\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "Null byte in cafile path: rejected\n";
}

// Very long path
$long_path = "/tmp/" . str_repeat("a", 4096) . ".pem";
try {
    $conn = new QuicConnection("quic.aiortc.org", 443, [
        "alpn" => ["hq-interop"],
        "cafile" => $long_path
    ]);
    echo "4KB path: accepted\n";
    unset($conn);
} catch (\Throwable $e) {
    echo "4KB path: rejected\n";
}

echo "No crash: yes\n";
echo "OK\n";
?>
--EXPECTF--
Non-existent cafile: rejected
/dev/null cafile: %s
Directory as cafile: %s
Non-existent capath: %s
Non-existent local_cert: rejected
Non-existent local_pk: rejected
Null byte in cafile path: %s
4KB path: rejected
No crash: yes
OK
