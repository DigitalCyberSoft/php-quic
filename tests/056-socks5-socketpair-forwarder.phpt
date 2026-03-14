--TEST--
SOCKS5 socketpair forwarder: full H3 connection through proxy
--EXTENSIONS--
quic
--SKIPIF--
<?php
if (!file_exists('/usr/bin/3proxy')) die("skip 3proxy not available");
?>
--FILE--
<?php

$port = rand(30000, 39999);
$logfile = "/tmp/3proxy-test-056-$port.log";
$cfgfile = "/tmp/3proxy-test-056-$port.cfg";
file_put_contents($cfgfile, "log $logfile\nsocks -p$port\n");
$proc = proc_open("3proxy $cfgfile", [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
if (!$proc) die("FAIL: could not start 3proxy\n");
usleep(300000);

try {
    $conn = quic_connect("www.cloudflare.com", 443, [
        "alpn" => ["h3"],
        "peer_name" => "www.cloudflare.com",
        "timeout" => 10,
        "verify_peer" => true,
        "socks5_proxy" => "127.0.0.1:$port",
    ]);
    echo "Connected: " . ($conn->isConnected() ? "yes" : "no") . "\n";
    echo "ALPN: " . $conn->getAlpn() . "\n";
    $conn->close();
    echo "Closed: " . ($conn->isConnected() ? "still connected" : "disconnected") . "\n";
} catch (RuntimeException $e) {
    echo "Exception: " . $e->getMessage() . "\n";
}

proc_terminate($proc);
proc_close($proc);
usleep(200000);

$log = file_exists($logfile) ? file_get_contents($logfile) : '';
echo "Proxy log has UDPMAP: " . (strpos($log, 'UDPMAP') !== false ? "yes" : "no") . "\n";

@unlink($cfgfile);
@unlink($logfile);
echo "OK\n";
?>
--EXPECT--
Connected: yes
ALPN: h3
Closed: disconnected
Proxy log has UDPMAP: yes
OK
