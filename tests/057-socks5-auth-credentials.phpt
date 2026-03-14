--TEST--
SOCKS5 with username/password authentication
--EXTENSIONS--
quic
--SKIPIF--
<?php
if (!file_exists('/usr/bin/3proxy')) die("skip 3proxy not available");
?>
--FILE--
<?php

$port = rand(30000, 39999);
$logfile = "/tmp/3proxy-test-057-$port.log";
$cfgfile = "/tmp/3proxy-test-057-$port.cfg";
file_put_contents($cfgfile, "log $logfile\nusers testuser:CL:testpass\nauth strong\nsocks -p$port\n");
$proc = proc_open("3proxy $cfgfile", [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
if (!$proc) die("FAIL: could not start 3proxy\n");
usleep(300000);

// Wrong password should fail
try {
    $conn = quic_connect("www.cloudflare.com", 443, [
        "alpn" => ["h3"],
        "peer_name" => "www.cloudflare.com",
        "timeout" => 5,
        "verify_peer" => true,
        "socks5_proxy" => "127.0.0.1:$port",
        "socks5_username" => "testuser",
        "socks5_password" => "wrongpass",
    ]);
    echo "FAIL: should have thrown with wrong password\n";
    $conn->close();
} catch (RuntimeException $e) {
    echo "Wrong password: caught error\n";
}

// Correct credentials should work
try {
    $conn = quic_connect("www.cloudflare.com", 443, [
        "alpn" => ["h3"],
        "peer_name" => "www.cloudflare.com",
        "timeout" => 10,
        "verify_peer" => true,
        "socks5_proxy" => "127.0.0.1:$port",
        "socks5_username" => "testuser",
        "socks5_password" => "testpass",
    ]);
    echo "Correct auth: " . ($conn->isConnected() ? "connected" : "failed") . "\n";
    echo "ALPN: " . $conn->getAlpn() . "\n";
    $conn->close();
} catch (RuntimeException $e) {
    echo "Exception: " . $e->getMessage() . "\n";
}

// No credentials when auth is required should fail
try {
    $conn = quic_connect("www.cloudflare.com", 443, [
        "alpn" => ["h3"],
        "peer_name" => "www.cloudflare.com",
        "timeout" => 5,
        "verify_peer" => true,
        "socks5_proxy" => "127.0.0.1:$port",
    ]);
    echo "FAIL: should have thrown without credentials\n";
    $conn->close();
} catch (RuntimeException $e) {
    echo "No credentials: caught error\n";
}

proc_terminate($proc);
proc_close($proc);
usleep(200000);

$log = file_exists($logfile) ? file_get_contents($logfile) : '';
echo "Proxy log has testuser: " . (strpos($log, 'testuser') !== false ? "yes" : "no") . "\n";

@unlink($cfgfile);
@unlink($logfile);
echo "OK\n";
?>
--EXPECT--
Wrong password: caught error
Correct auth: connected
ALPN: h3
No credentials: caught error
Proxy log has testuser: yes
OK
