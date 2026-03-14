--TEST--
SOCKS5 forwarder thread cleanup on connection close
--EXTENSIONS--
quic
--SKIPIF--
<?php
if (!file_exists('/usr/bin/3proxy')) die("skip 3proxy not available");
?>
--FILE--
<?php

$port = rand(30000, 39999);
$logfile = "/tmp/3proxy-test-058-$port.log";
$cfgfile = "/tmp/3proxy-test-058-$port.cfg";
file_put_contents($cfgfile, "log $logfile\nsocks -p$port\n");
$proc = proc_open("3proxy $cfgfile", [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
if (!$proc) die("FAIL: could not start 3proxy\n");
usleep(300000);

// Open and close multiple SOCKS5 connections to verify no resource leak
for ($i = 0; $i < 3; $i++) {
    try {
        $conn = quic_connect("www.cloudflare.com", 443, [
            "alpn" => ["h3"],
            "peer_name" => "www.cloudflare.com",
            "timeout" => 10,
            "verify_peer" => true,
            "socks5_proxy" => "127.0.0.1:$port",
        ]);
        echo "Connection $i: " . ($conn->isConnected() ? "connected" : "failed") . "\n";
        $conn->close();
        echo "Connection $i: " . ($conn->isConnected() ? "still connected" : "closed") . "\n";
    } catch (RuntimeException $e) {
        echo "Connection $i error: " . $e->getMessage() . "\n";
    }
}

$conn = null;
gc_collect_cycles();

// Verify we can still make connections (no fd exhaustion)
try {
    $conn = quic_connect("www.cloudflare.com", 443, [
        "alpn" => ["h3"],
        "peer_name" => "www.cloudflare.com",
        "timeout" => 10,
        "verify_peer" => true,
        "socks5_proxy" => "127.0.0.1:$port",
    ]);
    echo "Final connection: " . ($conn->isConnected() ? "connected" : "failed") . "\n";
    $conn->close();
} catch (RuntimeException $e) {
    echo "Final error: " . $e->getMessage() . "\n";
}

proc_terminate($proc);
proc_close($proc);
usleep(200000);

$log = file_exists($logfile) ? file_get_contents($logfile) : '';
$udpassoc_count = substr_count($log, 'UDPMAP');
echo "UDPMAP count in log: " . ($udpassoc_count >= 4 ? "4+" : $udpassoc_count) . "\n";

@unlink($cfgfile);
@unlink($logfile);
echo "OK\n";
?>
--EXPECT--
Connection 0: connected
Connection 0: closed
Connection 1: connected
Connection 1: closed
Connection 2: connected
Connection 2: closed
Final connection: connected
UDPMAP count in log: 4+
OK
