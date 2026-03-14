--TEST--
SOCKS5 proxy bidirectional data transfer through forwarder
--EXTENSIONS--
quic
--SKIPIF--
<?php
if (!file_exists('/usr/bin/3proxy')) die("skip 3proxy not available");
?>
--FILE--
<?php

$port = rand(30000, 39999);
$logfile = "/tmp/3proxy-test-060-$port.log";
$cfgfile = "/tmp/3proxy-test-060-$port.cfg";
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

    // Open bidi stream and write data
    $s1 = $conn->openStream(QUIC_STREAM_BIDI);
    echo "Stream 1 ID: " . $s1->getId() . "\n";
    echo "Stream 1 writable: " . ($s1->isWritable() ? "yes" : "no") . "\n";

    // Open uni stream
    $s2 = $conn->openStream(QUIC_STREAM_UNI);
    echo "Stream 2 writable: " . ($s2->isWritable() ? "yes" : "no") . "\n";

    // Write on stream 1
    $written = $s1->write("hello");
    echo "Written: $written bytes\n";
    $s1->conclude();

    // Stats should reflect traffic through the forwarder
    $stats = $conn->getStats();
    echo "Streams opened: " . $stats['streams_opened'] . "\n";
    echo "Bytes sent > 0: " . ($stats['bytes_sent'] > 0 ? "yes" : "no") . "\n";

    $conn->close();
    echo "Closed cleanly\n";
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
Stream 1 ID: 0
Stream 1 writable: yes
Stream 2 writable: yes
Written: 5 bytes
Streams opened: 2
Bytes sent > 0: yes
Closed cleanly
Proxy log has UDPMAP: yes
OK
