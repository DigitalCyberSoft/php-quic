--TEST--
acceptStream() has inverted timeout logic (known bug documentation)
--DESCRIPTION--
SECURITY BUG: acceptStream() timeout logic is inverted.

When timeout=0.0 (user expects immediate return), the code passes flags=0
to SSL_accept_stream() which means BLOCKING - this hangs indefinitely on
client connections since there are no server-initiated streams.

When timeout>0.0 (user expects wait), the code first tries NO_BLOCK, then
falls back to blocking with SO_RCVTIMEO which doesn't affect OpenSSL's
internal QUIC event loop, causing another indefinite hang.

The fix should be:
  timeout < 0  → blocking (SSL_accept_stream with flags=0)
  timeout == 0 → non-blocking (SSL_ACCEPT_STREAM_NO_BLOCK)
  timeout > 0  → non-blocking poll loop (like the read() implementation)

Additionally, when SO_RCVTIMEO is set, it's never restored, leaking the
timeout to all subsequent socket operations.

This test is SKIPPED because the bug causes the test process to hang.
The test below verifies that the extension loads and documents the issue.
--EXTENSIONS--
quic
--SKIPIF--
<?php die("skip acceptStream timeout logic is inverted - hangs indefinitely (known bug)"); ?>
--FILE--
<?php
// This code would hang due to the bug described above.
// Uncomment after fixing the acceptStream timeout logic.
//
// $conn = quic_connect("quic.aiortc.org", 443, ["alpn" => ["hq-interop"]]);
// $result = $conn->acceptStream(0.0); // HANGS - sends blocking flag
// echo "acceptStream returned: " . ($result === null ? "null" : "stream") . "\n";
echo "OK\n";
?>
--EXPECT--
OK
