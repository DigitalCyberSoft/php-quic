--TEST--
SOCKS5 handshake respects timeout option (does not hang for 30s)
--EXTENSIONS--
quic
--FILE--
<?php

// Start a fake SOCKS5 proxy that accepts auth then stalls (never replies to UDP ASSOCIATE)
$server = stream_socket_server("tcp://127.0.0.1:0", $errno, $errstr);
if (!$server) die("FAIL: $errstr\n");
$addr = stream_socket_get_name($server, false);
list($host, $port) = explode(":", $addr);

$fake_script = '/tmp/fake_socks5_065.php';
file_put_contents($fake_script, '<?php
$server = stream_socket_server("tcp://127.0.0.1:' . $port . '", $e, $es, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
if (!$server) exit(1);
$client = stream_socket_accept($server, 10);
if ($client) {
    // Read method negotiation
    fread($client, 3);
    // Reply: no auth required
    fwrite($client, "\x05\x00");
    // Read UDP ASSOCIATE request
    fread($client, 256);
    // Stall — never reply. This simulates the 3proxy ACL deny hang.
    sleep(30);
    fclose($client);
}
fclose($server);
');
fclose($server); // free the port

$proc = proc_open("php $fake_script", [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
usleep(200000);

$start = microtime(true);
try {
    $conn = quic_connect("www.cloudflare.com", 443, [
        "alpn" => ["h3"],
        "peer_name" => "www.cloudflare.com",
        "timeout" => 3,
        "socks5_proxy" => "127.0.0.1:$port",
    ]);
    echo "FAIL: should have thrown\n";
} catch (RuntimeException $e) {
    $elapsed = microtime(true) - $start;
    echo "Error caught\n";
    // Must fail in roughly 3 seconds, not 30
    echo "Timed out within 6s: " . ($elapsed < 6 ? "yes" : "no ($elapsed s)") . "\n";
    echo "Took at least 2s: " . ($elapsed >= 2 ? "yes" : "no ($elapsed s)") . "\n";
}

proc_terminate($proc);
proc_close($proc);
@unlink($fake_script);
echo "OK\n";
?>
--EXPECT--
Error caught
Timed out within 6s: yes
Took at least 2s: yes
OK
