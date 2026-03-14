--TEST--
SOCKS5 proxy that refuses UDP ASSOCIATE returns proper error
--EXTENSIONS--
quic
--FILE--
<?php

// Start a minimal fake SOCKS5 proxy that refuses UDP ASSOCIATE (reply 0x07)
$server = stream_socket_server("tcp://127.0.0.1:0", $errno, $errstr);
if (!$server) die("FAIL: $errstr\n");
$addr = stream_socket_get_name($server, false);
list($host, $port) = explode(":", $addr);

// Spawn the fake proxy as a background PHP process
$fake_script = '/tmp/fake_socks5_063.php';
file_put_contents($fake_script, '<?php
$server = stream_socket_server("tcp://127.0.0.1:' . $port . '", $e, $es, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
if (!$server) exit(1);
$client = stream_socket_accept($server, 5);
if ($client) {
    fread($client, 3);
    fwrite($client, "\x05\x00");
    fread($client, 256);
    fwrite($client, "\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00");
    usleep(100000);
    fclose($client);
}
fclose($server);
');
fclose($server); // free the port

$proc = proc_open("php $fake_script", [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
usleep(200000);

try {
    $conn = quic_connect("www.cloudflare.com", 443, [
        "alpn" => ["h3"],
        "peer_name" => "www.cloudflare.com",
        "timeout" => 5,
        "socks5_proxy" => "127.0.0.1:$port",
    ]);
    echo "FAIL: should have thrown\n";
} catch (RuntimeException $e) {
    $msg = $e->getMessage();
    echo "Error caught\n";
    echo "Contains 'command not supported': " . (strpos($msg, "command not supported") !== false ? "yes" : "no") . "\n";
}

proc_terminate($proc);
proc_close($proc);
@unlink($fake_script);
echo "OK\n";
?>
--EXPECT--
Error caught
Contains 'command not supported': yes
OK
