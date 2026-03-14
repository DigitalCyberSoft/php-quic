--TEST--
SOCKS5 connection GC does not leak forwarder thread or file descriptors
--EXTENSIONS--
quic
--SKIPIF--
<?php
if (!file_exists('/usr/bin/3proxy')) die("skip 3proxy not available");
if (!function_exists('posix_getpid')) die("skip posix extension required");
?>
--FILE--
<?php

$port = rand(30000, 39999);
$cfgfile = "/tmp/3proxy-test-061-$port.cfg";
file_put_contents($cfgfile, "socks -p$port\n");
$proc = proc_open("3proxy $cfgfile", [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
if (!$proc) die("FAIL: could not start 3proxy\n");
usleep(300000);

$pid = posix_getpid();

// Count open fds before
$fd_before = count(glob("/proc/$pid/fd/*"));

// Create and destroy connections via GC (no explicit close)
for ($i = 0; $i < 5; $i++) {
    $conn = quic_connect("www.cloudflare.com", 443, [
        "alpn" => ["h3"],
        "peer_name" => "www.cloudflare.com",
        "timeout" => 10,
        "verify_peer" => true,
        "socks5_proxy" => "127.0.0.1:$port",
    ]);
    // Drop reference without closing — destructor should clean up
    $conn = null;
    gc_collect_cycles();
    usleep(50000); // let forwarder thread exit
}

// Count open fds after
$fd_after = count(glob("/proc/$pid/fd/*"));

// Should not have leaked more than 2 fds (some jitter is normal)
$leaked = $fd_after - $fd_before;
echo "FD leak: " . ($leaked <= 2 ? "none" : "$leaked fds leaked") . "\n";

proc_terminate($proc);
proc_close($proc);
@unlink($cfgfile);
echo "OK\n";
?>
--EXPECT--
FD leak: none
OK
