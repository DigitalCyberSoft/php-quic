/*
 * php-quic: PHP extension for QUIC transport (RFC 9000)
 * Uses OpenSSL 3.2+ native QUIC client API.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "zend_exceptions.h"
#include "ext/spl/spl_exceptions.h"
#include "php_quic.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/quic.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

/* ----------------------------------------------------------------
 * Forward declarations
 * ---------------------------------------------------------------- */

static zend_class_entry *quic_connection_ce;
static zend_class_entry *quic_stream_ce;
static zend_object_handlers quic_connection_handlers;
static zend_object_handlers quic_stream_handlers;

static int quic_resolve_host(const char *host, int port, struct sockaddr_storage *addr, socklen_t *addrlen);

/* ----------------------------------------------------------------
 * SOCKS5 UDP relay BIO filter
 * Wraps outgoing datagrams with RFC 1928 UDP header, strips on receive.
 * Header: 2 bytes RSV (0x0000) + 1 byte FRAG (0x00) + ATYP + DST.ADDR + DST.PORT
 * ---------------------------------------------------------------- */

typedef struct {
	struct sockaddr_storage target_addr;
	socklen_t target_addr_len;
	uint8_t header[22]; /* max: 2 RSV + 1 FRAG + 1 ATYP + 16 IPv6 + 2 port = 22 */
	size_t header_len;
} socks5_bio_data;

static int socks5_bio_write_ex(BIO *bio, const char *data, size_t datal, size_t *written)
{
	BIO *next = BIO_next(bio);
	if (!next) return 0;

	socks5_bio_data *s5 = (socks5_bio_data *)BIO_get_data(bio);

	/* Prepend SOCKS5 UDP header to outgoing datagram */
	size_t total = s5->header_len + datal;
	char *buf = OPENSSL_malloc(total);
	if (!buf) return 0;

	memcpy(buf, s5->header, s5->header_len);
	memcpy(buf + s5->header_len, data, datal);

	int ret = BIO_write_ex(next, buf, total, written);
	OPENSSL_free(buf);

	/* Adjust written count to exclude our header */
	if (ret && *written >= s5->header_len)
		*written -= s5->header_len;

	return ret;
}

static int socks5_bio_read_ex(BIO *bio, char *data, size_t datal, size_t *readbytes)
{
	BIO *next = BIO_next(bio);
	if (!next) return 0;

	socks5_bio_data *s5 = (socks5_bio_data *)BIO_get_data(bio);

	/* Read into a temp buffer large enough for header + payload */
	size_t total = s5->header_len + datal;
	char *buf = OPENSSL_malloc(total);
	if (!buf) return 0;

	size_t got = 0;
	int ret = BIO_read_ex(next, buf, total, &got);
	if (!ret || got <= s5->header_len) {
		OPENSSL_free(buf);
		*readbytes = 0;
		return ret;
	}

	/* Strip SOCKS5 UDP header — the header length varies by ATYP in the response,
	 * but for simplicity parse the actual response header */
	size_t resp_hdr_len = 0;
	if (got >= 4) {
		uint8_t atyp = (uint8_t)buf[3];
		if (atyp == 0x01)       resp_hdr_len = 10; /* IPv4: 2+1+1+4+2 */
		else if (atyp == 0x04)  resp_hdr_len = 22; /* IPv6: 2+1+1+16+2 */
		else if (atyp == 0x03 && got >= 5) resp_hdr_len = 4 + 1 + (uint8_t)buf[4] + 2; /* domain */
		else resp_hdr_len = s5->header_len; /* fallback */
	} else {
		resp_hdr_len = s5->header_len;
	}

	if (got <= resp_hdr_len) {
		OPENSSL_free(buf);
		*readbytes = 0;
		return ret;
	}

	size_t payload_len = got - resp_hdr_len;
	if (payload_len > datal) payload_len = datal;
	memcpy(data, buf + resp_hdr_len, payload_len);
	*readbytes = payload_len;

	OPENSSL_free(buf);
	return ret;
}

static long socks5_bio_ctrl(BIO *bio, int cmd, long larg, void *parg)
{
	BIO *next = BIO_next(bio);
	if (!next) return 0;
	return BIO_ctrl(next, cmd, larg, parg);
}

static int socks5_bio_create(BIO *bio)
{
	BIO_set_init(bio, 1);
	return 1;
}

static int socks5_bio_destroy(BIO *bio)
{
	if (bio) {
		socks5_bio_data *s5 = (socks5_bio_data *)BIO_get_data(bio);
		if (s5) {
			OPENSSL_free(s5);
			BIO_set_data(bio, NULL);
		}
	}
	return 1;
}

static BIO_METHOD *socks5_bio_method = NULL;

static BIO_METHOD *get_socks5_bio_method(void)
{
	if (!socks5_bio_method) {
		socks5_bio_method = BIO_meth_new(BIO_TYPE_FILTER | BIO_get_new_index(),
			"socks5_udp_filter");
		BIO_meth_set_write_ex(socks5_bio_method, socks5_bio_write_ex);
		BIO_meth_set_read_ex(socks5_bio_method, socks5_bio_read_ex);
		BIO_meth_set_ctrl(socks5_bio_method, socks5_bio_ctrl);
		BIO_meth_set_create(socks5_bio_method, socks5_bio_create);
		BIO_meth_set_destroy(socks5_bio_method, socks5_bio_destroy);
	}
	return socks5_bio_method;
}

/* Build the SOCKS5 UDP header for a given target sockaddr */
static size_t socks5_build_header(uint8_t *header, struct sockaddr_storage *addr)
{
	header[0] = 0x00; /* RSV */
	header[1] = 0x00;
	header[2] = 0x00; /* FRAG */

	if (addr->ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;
		header[3] = 0x01; /* ATYP IPv4 */
		memcpy(header + 4, &sin->sin_addr, 4);
		memcpy(header + 8, &sin->sin_port, 2);
		return 10;
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
		header[3] = 0x04; /* ATYP IPv6 */
		memcpy(header + 4, &sin6->sin6_addr, 16);
		memcpy(header + 20, &sin6->sin6_port, 2);
		return 22;
	}
}

/* ----------------------------------------------------------------
 * SOCKS5 TCP handshake: auth + UDP ASSOCIATE
 *
 * Performs the full RFC 1928 handshake over a TCP connection to the
 * SOCKS5 proxy, then issues UDP ASSOCIATE. On success, writes the
 * relay address into relay_addr/relay_addr_len and returns the TCP
 * control socket fd (caller must keep it open).
 * Returns -1 on failure (sets errmsg).
 * ---------------------------------------------------------------- */

static int socks5_handshake(const char *proxy_host, int proxy_port,
	const char *username, const char *password,
	struct sockaddr_storage *bind_addr, socklen_t bind_addr_len,
	struct sockaddr_storage *relay_addr, socklen_t *relay_addr_len,
	char *errmsg, size_t errmsg_size)
{
	int tcp_fd = -1;
	struct sockaddr_storage proxy_addr;
	socklen_t proxy_addr_len;
	uint8_t buf[512];
	ssize_t n;

	/* Resolve proxy */
	if (quic_resolve_host(proxy_host, proxy_port, &proxy_addr, &proxy_addr_len) != 0) {
		snprintf(errmsg, errmsg_size, "Failed to resolve SOCKS5 proxy: %s", proxy_host);
		return -1;
	}

	/* TCP connect to proxy */
	tcp_fd = socket(proxy_addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (tcp_fd < 0) {
		snprintf(errmsg, errmsg_size, "Failed to create TCP socket: %s", strerror(errno));
		return -1;
	}

	struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
	setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(tcp_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	if (connect(tcp_fd, (struct sockaddr *)&proxy_addr, proxy_addr_len) < 0) {
		snprintf(errmsg, errmsg_size, "Failed to connect to SOCKS5 proxy: %s", strerror(errno));
		close(tcp_fd);
		return -1;
	}

	/* --- Auth negotiation (RFC 1928 section 3) --- */
	int has_auth = (username && password && strlen(username) > 0);

	if (has_auth) {
		/* Offer no-auth (0x00) and username/password (0x02) */
		buf[0] = 0x05; /* VER */
		buf[1] = 0x02; /* NMETHODS */
		buf[2] = 0x00; /* NO AUTH */
		buf[3] = 0x02; /* USERNAME/PASSWORD */
		if (send(tcp_fd, buf, 4, 0) != 4) goto io_err;
	} else {
		/* Offer no-auth only */
		buf[0] = 0x05;
		buf[1] = 0x01;
		buf[2] = 0x00;
		if (send(tcp_fd, buf, 3, 0) != 3) goto io_err;
	}

	/* Read method selection */
	n = recv(tcp_fd, buf, 2, MSG_WAITALL);
	if (n != 2 || buf[0] != 0x05) {
		snprintf(errmsg, errmsg_size, "SOCKS5 proxy returned invalid version");
		close(tcp_fd);
		return -1;
	}

	if (buf[1] == 0xFF) {
		snprintf(errmsg, errmsg_size, "SOCKS5 proxy: no acceptable auth method");
		close(tcp_fd);
		return -1;
	}

	/* Username/password auth (RFC 1929) */
	if (buf[1] == 0x02) {
		if (!has_auth) {
			snprintf(errmsg, errmsg_size, "SOCKS5 proxy requires authentication");
			close(tcp_fd);
			return -1;
		}
		size_t ulen = strlen(username);
		size_t plen = strlen(password);
		if (ulen > 255 || plen > 255) {
			snprintf(errmsg, errmsg_size, "SOCKS5 username/password too long");
			close(tcp_fd);
			return -1;
		}
		uint8_t *p = buf;
		*p++ = 0x01; /* subnegotiation version */
		*p++ = (uint8_t)ulen;
		memcpy(p, username, ulen); p += ulen;
		*p++ = (uint8_t)plen;
		memcpy(p, password, plen); p += plen;
		if (send(tcp_fd, buf, (size_t)(p - buf), 0) != (ssize_t)(p - buf)) goto io_err;

		n = recv(tcp_fd, buf, 2, MSG_WAITALL);
		if (n != 2 || buf[1] != 0x00) {
			snprintf(errmsg, errmsg_size, "SOCKS5 authentication failed");
			close(tcp_fd);
			return -1;
		}
	} else if (buf[1] != 0x00) {
		snprintf(errmsg, errmsg_size, "SOCKS5 proxy selected unsupported auth method 0x%02x", buf[1]);
		close(tcp_fd);
		return -1;
	}

	/* --- UDP ASSOCIATE request (RFC 1928 section 4) ---
	 * DST.ADDR/DST.PORT = our local bind address so proxy knows where
	 * to expect UDP from. If we don't know yet, use 0.0.0.0:0. */
	{
		uint8_t *p = buf;
		*p++ = 0x05; /* VER */
		*p++ = 0x03; /* CMD = UDP ASSOCIATE */
		*p++ = 0x00; /* RSV */

		if (bind_addr && bind_addr->ss_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)bind_addr;
			*p++ = 0x01; /* ATYP IPv4 */
			memcpy(p, &sin->sin_addr, 4); p += 4;
			memcpy(p, &sin->sin_port, 2); p += 2;
		} else if (bind_addr && bind_addr->ss_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)bind_addr;
			*p++ = 0x04; /* ATYP IPv6 */
			memcpy(p, &sin6->sin6_addr, 16); p += 16;
			memcpy(p, &sin6->sin6_port, 2); p += 2;
		} else {
			/* Unknown / unbound — send 0.0.0.0:0 */
			*p++ = 0x01;
			memset(p, 0, 6); p += 6;
		}

		if (send(tcp_fd, buf, (size_t)(p - buf), 0) != (ssize_t)(p - buf)) goto io_err;
	}

	/* --- Read UDP ASSOCIATE reply --- */
	n = recv(tcp_fd, buf, 4, MSG_WAITALL);
	if (n != 4 || buf[0] != 0x05) {
		snprintf(errmsg, errmsg_size, "SOCKS5 UDP ASSOCIATE: invalid reply");
		close(tcp_fd);
		return -1;
	}
	if (buf[1] != 0x00) {
		const char *reason;
		switch (buf[1]) {
			case 0x01: reason = "general failure"; break;
			case 0x02: reason = "connection not allowed"; break;
			case 0x03: reason = "network unreachable"; break;
			case 0x04: reason = "host unreachable"; break;
			case 0x05: reason = "connection refused"; break;
			case 0x07: reason = "command not supported"; break;
			case 0x08: reason = "address type not supported"; break;
			default:   reason = "unknown error"; break;
		}
		snprintf(errmsg, errmsg_size, "SOCKS5 UDP ASSOCIATE failed: %s (0x%02x)", reason, buf[1]);
		close(tcp_fd);
		return -1;
	}

	/* Parse BND.ADDR + BND.PORT — the relay endpoint */
	uint8_t atyp = buf[3];
	if (atyp == 0x01) {
		/* IPv4 */
		uint8_t addr_buf[6]; /* 4 addr + 2 port */
		n = recv(tcp_fd, addr_buf, 6, MSG_WAITALL);
		if (n != 6) goto io_err;
		struct sockaddr_in *sin = (struct sockaddr_in *)relay_addr;
		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, addr_buf, 4);
		memcpy(&sin->sin_port, addr_buf + 4, 2);
		*relay_addr_len = sizeof(struct sockaddr_in);

		/* If relay address is 0.0.0.0, use the proxy's address instead */
		if (sin->sin_addr.s_addr == INADDR_ANY) {
			if (proxy_addr.ss_family == AF_INET) {
				sin->sin_addr = ((struct sockaddr_in *)&proxy_addr)->sin_addr;
			}
		}
	} else if (atyp == 0x04) {
		/* IPv6 */
		uint8_t addr_buf[18]; /* 16 addr + 2 port */
		n = recv(tcp_fd, addr_buf, 18, MSG_WAITALL);
		if (n != 18) goto io_err;
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)relay_addr;
		memset(sin6, 0, sizeof(*sin6));
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, addr_buf, 16);
		memcpy(&sin6->sin6_port, addr_buf + 16, 2);
		*relay_addr_len = sizeof(struct sockaddr_in6);

		/* If relay address is ::, use the proxy's address instead */
		static const uint8_t zeroes[16] = {0};
		if (memcmp(&sin6->sin6_addr, zeroes, 16) == 0) {
			if (proxy_addr.ss_family == AF_INET6) {
				sin6->sin6_addr = ((struct sockaddr_in6 *)&proxy_addr)->sin6_addr;
			}
		}
	} else if (atyp == 0x03) {
		/* Domain name — unusual for UDP ASSOCIATE but handle it */
		uint8_t dlen;
		n = recv(tcp_fd, &dlen, 1, MSG_WAITALL);
		if (n != 1) goto io_err;
		char domain[256];
		n = recv(tcp_fd, domain, dlen, MSG_WAITALL);
		if (n != dlen) goto io_err;
		domain[dlen] = '\0';
		uint8_t port_buf[2];
		n = recv(tcp_fd, port_buf, 2, MSG_WAITALL);
		if (n != 2) goto io_err;
		int rport = (port_buf[0] << 8) | port_buf[1];
		if (quic_resolve_host(domain, rport, relay_addr, relay_addr_len) != 0) {
			snprintf(errmsg, errmsg_size, "Failed to resolve SOCKS5 relay address: %s", domain);
			close(tcp_fd);
			return -1;
		}
	} else {
		snprintf(errmsg, errmsg_size, "SOCKS5 UDP ASSOCIATE: unsupported ATYP 0x%02x", atyp);
		close(tcp_fd);
		return -1;
	}

	return tcp_fd;

io_err:
	snprintf(errmsg, errmsg_size, "SOCKS5 handshake I/O error: %s", strerror(errno));
	close(tcp_fd);
	return -1;
}

/* ----------------------------------------------------------------
 * QuicConnection object
 * ---------------------------------------------------------------- */

typedef struct {
	SSL_CTX *ctx;
	SSL *ssl;
	int fd;
	char *host;
	char *peer_name;
	int port;
	char *socks5_proxy;  /* "host:port" of SOCKS5 proxy */
	char *socks5_username;
	char *socks5_password;
	int socks5_ctrl_fd;  /* TCP control socket — must stay open for relay lifetime */
	zend_bool connected;
	zend_bool verify_peer;
	zend_bool verify_peer_name;
	zend_bool allow_self_signed;
	uint32_t stream_count;
	uint64_t bytes_sent;
	uint64_t bytes_received;
	uint32_t streams_opened;
	zend_object std;
} quic_connection_obj;

static inline quic_connection_obj *quic_connection_from_obj(zend_object *obj)
{
	return (quic_connection_obj *)((char *)obj - XtOffsetOf(quic_connection_obj, std));
}

#define Z_QUIC_CONNECTION_P(zv) quic_connection_from_obj(Z_OBJ_P(zv))

/* ----------------------------------------------------------------
 * QuicStream object
 * ---------------------------------------------------------------- */

typedef struct {
	SSL *stream_ssl;
	zend_object *conn_zobj;
	zend_object std;
} quic_stream_obj;

static inline quic_stream_obj *quic_stream_from_obj(zend_object *obj)
{
	return (quic_stream_obj *)((char *)obj - XtOffsetOf(quic_stream_obj, std));
}

#define Z_QUIC_STREAM_P(zv) quic_stream_from_obj(Z_OBJ_P(zv))

/* ----------------------------------------------------------------
 * Helper: get OpenSSL error string
 * ---------------------------------------------------------------- */

static void quic_throw_ssl_error(const char *prefix)
{
	unsigned long err = ERR_peek_last_error();
	if (err) {
		char buf[256];
		ERR_error_string_n(err, buf, sizeof(buf));
		zend_throw_exception_ex(spl_ce_RuntimeException, 0, "%s: %s", prefix, buf);
		ERR_clear_error();
	} else {
		zend_throw_exception(spl_ce_RuntimeException, prefix, 0);
	}
}

/* ----------------------------------------------------------------
 * Helper: resolve hostname to sockaddr for UDP
 * ---------------------------------------------------------------- */

static int quic_resolve_host(const char *host, int port, struct sockaddr_storage *addr, socklen_t *addrlen)
{
	struct addrinfo hints, *res;
	char port_str[8];
	int rv;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	snprintf(port_str, sizeof(port_str), "%d", port);

	rv = getaddrinfo(host, port_str, &hints, &res);
	if (rv != 0) {
		return -1;
	}

	memcpy(addr, res->ai_addr, res->ai_addrlen);
	*addrlen = res->ai_addrlen;
	freeaddrinfo(res);

	return 0;
}

/* ----------------------------------------------------------------
 * Helper: build ALPN wire format from PHP array
 * ---------------------------------------------------------------- */

static unsigned char *quic_build_alpn(zval *alpn_arr, unsigned int *out_len)
{
	zval *entry;
	unsigned int total = 0;
	unsigned char *buf, *p;

	/* First pass: calculate total length */
	ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(alpn_arr), entry) {
		if (Z_TYPE_P(entry) != IS_STRING) {
			return NULL;
		}
		if (Z_STRLEN_P(entry) == 0 || Z_STRLEN_P(entry) > 255) {
			return NULL;
		}
		total += 1 + (unsigned int)Z_STRLEN_P(entry);
	} ZEND_HASH_FOREACH_END();

	if (total == 0) {
		return NULL;
	}

	buf = emalloc(total);
	p = buf;

	/* Second pass: build wire format */
	ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(alpn_arr), entry) {
		*p++ = (unsigned char)Z_STRLEN_P(entry);
		memcpy(p, Z_STRVAL_P(entry), Z_STRLEN_P(entry));
		p += Z_STRLEN_P(entry);
	} ZEND_HASH_FOREACH_END();

	*out_len = total;
	return buf;
}

/* ----------------------------------------------------------------
 * Verify callback: accept self-signed certificates
 * ---------------------------------------------------------------- */

static int quic_verify_allow_self_signed(int preverify_ok, X509_STORE_CTX *ctx)
{
	if (preverify_ok)
		return 1;
	int err = X509_STORE_CTX_get_error(ctx);
	if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
		err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
		return 1;
	}
	return 0;
}

/* ----------------------------------------------------------------
 * QuicConnection free handler
 * ---------------------------------------------------------------- */

static void quic_connection_free(zend_object *object)
{
	quic_connection_obj *conn = quic_connection_from_obj(object);

	if (conn->ssl) {
		if (conn->connected) {
			SSL_SHUTDOWN_EX_ARGS args = {0};
			SSL_shutdown_ex(conn->ssl, SSL_SHUTDOWN_FLAG_RAPID, &args, sizeof(args));
		}
		SSL_free(conn->ssl);
		conn->ssl = NULL;
	}
	if (conn->ctx) {
		SSL_CTX_free(conn->ctx);
		conn->ctx = NULL;
	}
	if (conn->fd >= 0) {
		close(conn->fd);
		conn->fd = -1;
	}
	if (conn->host) {
		efree(conn->host);
		conn->host = NULL;
	}
	if (conn->peer_name) {
		efree(conn->peer_name);
		conn->peer_name = NULL;
	}
	if (conn->socks5_proxy) {
		efree(conn->socks5_proxy);
		conn->socks5_proxy = NULL;
	}
	if (conn->socks5_username) {
		efree(conn->socks5_username);
		conn->socks5_username = NULL;
	}
	if (conn->socks5_password) {
		efree(conn->socks5_password);
		conn->socks5_password = NULL;
	}
	if (conn->socks5_ctrl_fd >= 0) {
		close(conn->socks5_ctrl_fd);
		conn->socks5_ctrl_fd = -1;
	}

	zend_object_std_dtor(&conn->std);
}

/* ----------------------------------------------------------------
 * QuicConnection create handler
 * ---------------------------------------------------------------- */

static zend_object *quic_connection_create(zend_class_entry *ce)
{
	quic_connection_obj *conn = zend_object_alloc(sizeof(quic_connection_obj), ce);

	conn->ctx = NULL;
	conn->ssl = NULL;
	conn->fd = -1;
	conn->host = NULL;
	conn->peer_name = NULL;
	conn->socks5_proxy = NULL;
	conn->socks5_username = NULL;
	conn->socks5_password = NULL;
	conn->socks5_ctrl_fd = -1;
	conn->port = 0;
	conn->connected = 0;
	conn->verify_peer = 1;
	conn->verify_peer_name = 1;
	conn->allow_self_signed = 0;
	conn->stream_count = 0;
	conn->bytes_sent = 0;
	conn->bytes_received = 0;
	conn->streams_opened = 0;

	zend_object_std_init(&conn->std, ce);
	object_properties_init(&conn->std, ce);
	conn->std.handlers = &quic_connection_handlers;

	return &conn->std;
}

/* ----------------------------------------------------------------
 * QuicStream free handler
 * ---------------------------------------------------------------- */

static void quic_stream_free(zend_object *object)
{
	quic_stream_obj *stream = quic_stream_from_obj(object);

	if (stream->stream_ssl) {
		SSL_free(stream->stream_ssl);
		stream->stream_ssl = NULL;
	}

	if (stream->conn_zobj) {
		quic_connection_obj *conn = quic_connection_from_obj(stream->conn_zobj);
		conn->stream_count--;
		OBJ_RELEASE(stream->conn_zobj);
		stream->conn_zobj = NULL;
	}

	zend_object_std_dtor(&stream->std);
}

/* ----------------------------------------------------------------
 * QuicStream create handler
 * ---------------------------------------------------------------- */

static zend_object *quic_stream_create(zend_class_entry *ce)
{
	quic_stream_obj *stream = zend_object_alloc(sizeof(quic_stream_obj), ce);

	stream->stream_ssl = NULL;
	stream->conn_zobj = NULL;

	zend_object_std_init(&stream->std, ce);
	object_properties_init(&stream->std, ce);
	stream->std.handlers = &quic_stream_handlers;

	return &stream->std;
}

/* ----------------------------------------------------------------
 * QuicConnection::__construct(string $host, int $port, array $options = [])
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicConnection, __construct)
{
	char *host;
	size_t host_len;
	zend_long port;
	zval *options = NULL;
	quic_connection_obj *conn;
	SSL_CTX *ctx;

	ZEND_PARSE_PARAMETERS_START(2, 3)
		Z_PARAM_STRING(host, host_len)
		Z_PARAM_LONG(port)
		Z_PARAM_OPTIONAL
		Z_PARAM_ARRAY(options)
	ZEND_PARSE_PARAMETERS_END();

	if (port < 1 || port > 65535) {
		zend_throw_exception(zend_ce_value_error, "Port must be between 1 and 65535", 0);
		RETURN_THROWS();
	}

	if (host_len == 0) {
		zend_throw_exception(zend_ce_value_error, "Host must not be empty", 0);
		RETURN_THROWS();
	}

	conn = Z_QUIC_CONNECTION_P(ZEND_THIS);

	/* Create SSL_CTX with QUIC client method */
	ctx = SSL_CTX_new(OSSL_QUIC_client_method());
	if (!ctx) {
		quic_throw_ssl_error("Failed to create QUIC SSL context");
		RETURN_THROWS();
	}

	conn->ctx = ctx;
	conn->host = estrndup(host, host_len);
	conn->port = (int)port;

	/* Process options */
	zval *opt_val;

	if (options) {
		/* ALPN */
		opt_val = zend_hash_str_find(Z_ARRVAL_P(options), "alpn", sizeof("alpn") - 1);
		if (opt_val && Z_TYPE_P(opt_val) == IS_ARRAY) {
			unsigned int alpn_len = 0;
			unsigned char *alpn_buf = quic_build_alpn(opt_val, &alpn_len);
			if (alpn_buf) {
				SSL_CTX_set_alpn_protos(ctx, alpn_buf, alpn_len);
				efree(alpn_buf);
			} else {
				zend_throw_exception(zend_ce_value_error,
					"ALPN protocols must be non-empty strings (max 255 bytes each)", 0);
				RETURN_THROWS();
			}
		}

		/* verify_peer */
		opt_val = zend_hash_str_find(Z_ARRVAL_P(options), "verify_peer", sizeof("verify_peer") - 1);
		if (opt_val) {
			conn->verify_peer = zend_is_true(opt_val);
		}

		/* verify_peer_name */
		opt_val = zend_hash_str_find(Z_ARRVAL_P(options), "verify_peer_name", sizeof("verify_peer_name") - 1);
		if (opt_val) {
			conn->verify_peer_name = zend_is_true(opt_val);
		}

		/* allow_self_signed */
		opt_val = zend_hash_str_find(Z_ARRVAL_P(options), "allow_self_signed", sizeof("allow_self_signed") - 1);
		if (opt_val) {
			conn->allow_self_signed = zend_is_true(opt_val);
		}

		/* peer_name - overrides host for SNI and hostname verification */
		opt_val = zend_hash_str_find(Z_ARRVAL_P(options), "peer_name", sizeof("peer_name") - 1);
		if (opt_val && Z_TYPE_P(opt_val) == IS_STRING && Z_STRLEN_P(opt_val) > 0) {
			conn->peer_name = estrndup(Z_STRVAL_P(opt_val), Z_STRLEN_P(opt_val));
		}

		/* ciphersuites - TLS 1.3 cipher suite selection (QUIC requires TLS 1.3) */
		opt_val = zend_hash_str_find(Z_ARRVAL_P(options), "ciphersuites", sizeof("ciphersuites") - 1);
		if (opt_val && Z_TYPE_P(opt_val) == IS_STRING) {
			if (!SSL_CTX_set_ciphersuites(ctx, Z_STRVAL_P(opt_val))) {
				quic_throw_ssl_error("Failed to set TLS 1.3 ciphersuites");
				RETURN_THROWS();
			}
		}

		/* cafile */
		opt_val = zend_hash_str_find(Z_ARRVAL_P(options), "cafile", sizeof("cafile") - 1);
		if (opt_val && Z_TYPE_P(opt_val) == IS_STRING) {
			if (!SSL_CTX_load_verify_file(ctx, Z_STRVAL_P(opt_val))) {
				quic_throw_ssl_error("Failed to load CA file");
				RETURN_THROWS();
			}
		}

		/* capath */
		opt_val = zend_hash_str_find(Z_ARRVAL_P(options), "capath", sizeof("capath") - 1);
		if (opt_val && Z_TYPE_P(opt_val) == IS_STRING) {
			if (!SSL_CTX_load_verify_dir(ctx, Z_STRVAL_P(opt_val))) {
				quic_throw_ssl_error("Failed to load CA path");
				RETURN_THROWS();
			}
		}

		/* local_cert */
		opt_val = zend_hash_str_find(Z_ARRVAL_P(options), "local_cert", sizeof("local_cert") - 1);
		if (opt_val && Z_TYPE_P(opt_val) == IS_STRING) {
			if (!SSL_CTX_use_certificate_chain_file(ctx, Z_STRVAL_P(opt_val))) {
				quic_throw_ssl_error("Failed to load client certificate");
				RETURN_THROWS();
			}
		}

		/* local_pk */
		opt_val = zend_hash_str_find(Z_ARRVAL_P(options), "local_pk", sizeof("local_pk") - 1);
		if (opt_val && Z_TYPE_P(opt_val) == IS_STRING) {
			if (!SSL_CTX_use_PrivateKey_file(ctx, Z_STRVAL_P(opt_val), SSL_FILETYPE_PEM)) {
				quic_throw_ssl_error("Failed to load client private key");
				RETURN_THROWS();
			}
		}

		/* socks5_proxy - "host:port" of SOCKS5 proxy for tunneling QUIC over UDP relay */
		opt_val = zend_hash_str_find(Z_ARRVAL_P(options), "socks5_proxy", sizeof("socks5_proxy") - 1);
		if (opt_val && Z_TYPE_P(opt_val) == IS_STRING && Z_STRLEN_P(opt_val) > 0) {
			conn->socks5_proxy = estrndup(Z_STRVAL_P(opt_val), Z_STRLEN_P(opt_val));
		}

		/* socks5_username / socks5_password - optional auth for SOCKS5 proxy */
		opt_val = zend_hash_str_find(Z_ARRVAL_P(options), "socks5_username", sizeof("socks5_username") - 1);
		if (opt_val && Z_TYPE_P(opt_val) == IS_STRING && Z_STRLEN_P(opt_val) > 0) {
			conn->socks5_username = estrndup(Z_STRVAL_P(opt_val), Z_STRLEN_P(opt_val));
		}
		opt_val = zend_hash_str_find(Z_ARRVAL_P(options), "socks5_password", sizeof("socks5_password") - 1);
		if (opt_val && Z_TYPE_P(opt_val) == IS_STRING && Z_STRLEN_P(opt_val) > 0) {
			conn->socks5_password = estrndup(Z_STRVAL_P(opt_val), Z_STRLEN_P(opt_val));
		}
	}

	/* Set verification mode */
	if (conn->verify_peer) {
		if (conn->allow_self_signed) {
			SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, quic_verify_allow_self_signed);
		} else {
			SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		}
		SSL_CTX_set_default_verify_paths(ctx);
	} else {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	}
}

/* ----------------------------------------------------------------
 * QuicConnection::connect(): bool
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicConnection, connect)
{
	quic_connection_obj *conn;
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	BIO_ADDR *bio_addr = NULL;
	BIO *bio = NULL;
	int fd = -1;
	double timeout_val = 30.0;
	zend_long idle_timeout = 0;

	ZEND_PARSE_PARAMETERS_NONE();

	conn = Z_QUIC_CONNECTION_P(ZEND_THIS);

	if (conn->connected) {
		zend_throw_exception(spl_ce_RuntimeException, "Already connected", 0);
		RETURN_THROWS();
	}

	if (!conn->ctx) {
		zend_throw_exception(spl_ce_RuntimeException, "QUIC context not initialized", 0);
		RETURN_THROWS();
	}

	/* Check for timeout option - need to re-read from constructor options
	 * We stored the ctx, so check if we need to get timeout from the object.
	 * For simplicity, use the default or parse from the zval stored. */

	/* Resolve the real target */
	if (quic_resolve_host(conn->host, conn->port, &peer_addr, &peer_addr_len) != 0) {
		zend_throw_exception_ex(spl_ce_RuntimeException, 0,
			"Failed to resolve host: %s", conn->host);
		RETURN_THROWS();
	}

	/* Determine where the UDP socket should connect:
	 * - Direct: connect to peer_addr (the target)
	 * - SOCKS5: perform TCP handshake, get relay address from proxy */
	struct sockaddr_storage connect_addr;
	socklen_t connect_addr_len;

	if (conn->socks5_proxy) {
		/* Parse proxy "host:port" */
		char proxy_buf[256];
		strncpy(proxy_buf, conn->socks5_proxy, sizeof(proxy_buf) - 1);
		proxy_buf[sizeof(proxy_buf) - 1] = '\0';
		char *colon = strrchr(proxy_buf, ':');
		if (!colon) {
			zend_throw_exception(spl_ce_RuntimeException,
				"Invalid socks5_proxy format, expected host:port", 0);
			RETURN_THROWS();
		}
		*colon = '\0';
		int proxy_port = atoi(colon + 1);

		/* Perform SOCKS5 TCP handshake + UDP ASSOCIATE */
		char errmsg[512];
		int ctrl_fd = socks5_handshake(
			proxy_buf, proxy_port,
			conn->socks5_username, conn->socks5_password,
			NULL, 0,  /* bind addr not known yet */
			&connect_addr, &connect_addr_len,
			errmsg, sizeof(errmsg));
		if (ctrl_fd < 0) {
			zend_throw_exception(spl_ce_RuntimeException, errmsg, 0);
			RETURN_THROWS();
		}
		conn->socks5_ctrl_fd = ctrl_fd;
	} else {
		memcpy(&connect_addr, &peer_addr, peer_addr_len);
		connect_addr_len = peer_addr_len;
	}

	/* Create UDP socket */
	fd = socket(connect_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		zend_throw_exception_ex(spl_ce_RuntimeException, 0,
			"Failed to create UDP socket: %s", strerror(errno));
		RETURN_THROWS();
	}

	/* Set receive timeout on socket */
	struct timeval tv;
	tv.tv_sec = (long)timeout_val;
	tv.tv_usec = (long)((timeout_val - (double)tv.tv_sec) * 1000000.0);
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	/* Create SSL object */
	conn->ssl = SSL_new(conn->ctx);
	if (!conn->ssl) {
		close(fd);
		quic_throw_ssl_error("Failed to create QUIC SSL object");
		RETURN_THROWS();
	}

	/* Set SNI hostname - use peer_name if provided, otherwise host */
	const char *sni_name = conn->peer_name ? conn->peer_name : conn->host;
	SSL_set_tlsext_host_name(conn->ssl, sni_name);

	/* Set hostname verification if verify_peer and verify_peer_name are both enabled */
	if (conn->verify_peer && conn->verify_peer_name) {
		SSL_set1_host(conn->ssl, sni_name);
	}

	/* Create BIO for the UDP socket */
	bio = BIO_new_dgram(fd, BIO_NOCLOSE);
	if (!bio) {
		close(fd);
		quic_throw_ssl_error("Failed to create datagram BIO");
		RETURN_THROWS();
	}

	/* Set peer address via BIO_ADDR */
	bio_addr = BIO_ADDR_new();
	if (!bio_addr) {
		BIO_free(bio);
		close(fd);
		quic_throw_ssl_error("Failed to create BIO_ADDR");
		RETURN_THROWS();
	}

	/* Connect UDP socket to target (direct) or relay (SOCKS5) */
	if (connect(fd, (struct sockaddr *)&connect_addr, connect_addr_len) < 0) {
		BIO_ADDR_free(bio_addr);
		BIO_free(bio);
		close(fd);
		zend_throw_exception_ex(spl_ce_RuntimeException, 0,
			"Failed to connect UDP socket: %s", strerror(errno));
		RETURN_THROWS();
	}

	/* If SOCKS5, insert BIO filter that wraps/unwraps UDP relay headers */
	if (conn->socks5_proxy) {
		BIO *filter = BIO_new(get_socks5_bio_method());
		if (!filter) {
			BIO_ADDR_free(bio_addr);
			BIO_free(bio);
			close(fd);
			zend_throw_exception(spl_ce_RuntimeException,
				"Failed to create SOCKS5 BIO filter", 0);
			RETURN_THROWS();
		}

		socks5_bio_data *s5 = OPENSSL_zalloc(sizeof(socks5_bio_data));
		memcpy(&s5->target_addr, &peer_addr, peer_addr_len);
		s5->target_addr_len = peer_addr_len;
		s5->header_len = socks5_build_header(s5->header, &peer_addr);
		BIO_set_data(filter, s5);

		/* Chain: SSL -> socks5_filter -> dgram_bio */
		bio = BIO_push(filter, bio);
	}

	SSL_set_bio(conn->ssl, bio, bio);
	conn->fd = fd;

	/* Set initial peer address for QUIC */
	/* With a connected UDP socket, we set the peer addr from sockaddr */
	{
		BIO_ADDR *peer_bio_addr = BIO_ADDR_new();
		if (peer_bio_addr) {
			/* Use BIO_dgram_get_peer to let OpenSSL know the peer,
			 * or set it via SSL_set1_initial_peer_addr */
			if (peer_addr.ss_family == AF_INET) {
				struct sockaddr_in *sin = (struct sockaddr_in *)&peer_addr;
				BIO_ADDR_rawmake(peer_bio_addr, AF_INET,
					&sin->sin_addr, sizeof(sin->sin_addr), sin->sin_port);
			} else if (peer_addr.ss_family == AF_INET6) {
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&peer_addr;
				BIO_ADDR_rawmake(peer_bio_addr, AF_INET6,
					&sin6->sin6_addr, sizeof(sin6->sin6_addr), sin6->sin6_port);
			}
			SSL_set1_initial_peer_addr(conn->ssl, peer_bio_addr);
			BIO_ADDR_free(peer_bio_addr);
		}
	}

	BIO_ADDR_free(bio_addr);

	/* Use blocking mode for the handshake */
	SSL_set_blocking_mode(conn->ssl, 1);

	/* Perform QUIC handshake */
	if (SSL_connect(conn->ssl) <= 0) {
		quic_throw_ssl_error("QUIC handshake failed");
		RETURN_THROWS();
	}

	conn->connected = 1;
	RETURN_TRUE;
}

/* ----------------------------------------------------------------
 * QuicConnection::close(int $errorCode = 0, string $reason = ''): bool
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicConnection, close)
{
	quic_connection_obj *conn;
	zend_long error_code = 0;
	char *reason = "";
	size_t reason_len = 0;

	ZEND_PARSE_PARAMETERS_START(0, 2)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(error_code)
		Z_PARAM_STRING(reason, reason_len)
	ZEND_PARSE_PARAMETERS_END();

	conn = Z_QUIC_CONNECTION_P(ZEND_THIS);

	if (!conn->connected || !conn->ssl) {
		RETURN_FALSE;
	}

	SSL_SHUTDOWN_EX_ARGS args = {0};
	args.quic_error_code = (uint64_t)error_code;
	args.quic_reason = reason;

	int ret = SSL_shutdown_ex(conn->ssl, SSL_SHUTDOWN_FLAG_RAPID, &args, sizeof(args));
	conn->connected = 0;

	/* Close SOCKS5 TCP control socket — relay terminates when this closes */
	if (conn->socks5_ctrl_fd >= 0) {
		close(conn->socks5_ctrl_fd);
		conn->socks5_ctrl_fd = -1;
	}

	RETURN_BOOL(ret >= 0);
}

/* ----------------------------------------------------------------
 * QuicConnection::isConnected(): bool
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicConnection, isConnected)
{
	quic_connection_obj *conn;

	ZEND_PARSE_PARAMETERS_NONE();

	conn = Z_QUIC_CONNECTION_P(ZEND_THIS);
	RETURN_BOOL(conn->connected);
}

/* ----------------------------------------------------------------
 * QuicConnection::getAlpn(): ?string
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicConnection, getAlpn)
{
	quic_connection_obj *conn;
	const unsigned char *alpn_data = NULL;
	unsigned int alpn_len = 0;

	ZEND_PARSE_PARAMETERS_NONE();

	conn = Z_QUIC_CONNECTION_P(ZEND_THIS);

	if (!conn->ssl) {
		RETURN_NULL();
	}

	SSL_get0_alpn_selected(conn->ssl, &alpn_data, &alpn_len);
	if (alpn_data && alpn_len > 0) {
		RETURN_STRINGL((const char *)alpn_data, alpn_len);
	}

	RETURN_NULL();
}

/* ----------------------------------------------------------------
 * QuicConnection::getPeerCertificate(): ?OpenSSLCertificate
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicConnection, getPeerCertificate)
{
	quic_connection_obj *conn;
	X509 *cert;

	ZEND_PARSE_PARAMETERS_NONE();

	conn = Z_QUIC_CONNECTION_P(ZEND_THIS);

	if (!conn->ssl) {
		RETURN_NULL();
	}

	cert = SSL_get1_peer_certificate(conn->ssl);
	if (!cert) {
		RETURN_NULL();
	}

	/* Create an OpenSSLCertificate object */
	zend_class_entry *ossl_cert_ce = zend_lookup_class(
		zend_string_init("OpenSSLCertificate", sizeof("OpenSSLCertificate") - 1, 0));

	if (!ossl_cert_ce) {
		X509_free(cert);
		RETURN_NULL();
	}

	/* Use PHP's openssl extension to wrap the X509 */
	/* We return the PEM-encoded cert as a string and let the user
	 * use openssl_x509_read() if they need the object. This avoids
	 * depending on PHP openssl extension internals. */
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio) {
		X509_free(cert);
		RETURN_NULL();
	}

	PEM_write_bio_X509(bio, cert);
	X509_free(cert);

	char *pem_data = NULL;
	long pem_len = BIO_get_mem_data(bio, &pem_data);
	if (pem_data && pem_len > 0) {
		RETVAL_STRINGL(pem_data, pem_len);
	} else {
		RETVAL_NULL();
	}
	BIO_free(bio);
}

/* ----------------------------------------------------------------
 * QuicConnection::getStats(): array
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicConnection, getStats)
{
	quic_connection_obj *conn;

	ZEND_PARSE_PARAMETERS_NONE();

	conn = Z_QUIC_CONNECTION_P(ZEND_THIS);

	array_init(return_value);
	add_assoc_long(return_value, "bytes_sent", (zend_long)conn->bytes_sent);
	add_assoc_long(return_value, "bytes_received", (zend_long)conn->bytes_received);
	add_assoc_long(return_value, "streams_opened", (zend_long)conn->streams_opened);
}

/* ----------------------------------------------------------------
 * QuicConnection::openStream(int $type = QUIC_STREAM_BIDI): QuicStream
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicConnection, openStream)
{
	quic_connection_obj *conn;
	zend_long type = SSL_STREAM_TYPE_BIDI;
	SSL *stream_ssl;
	quic_stream_obj *stream;
	uint64_t flags = 0;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(type)
	ZEND_PARSE_PARAMETERS_END();

	conn = Z_QUIC_CONNECTION_P(ZEND_THIS);

	if (!conn->connected || !conn->ssl) {
		zend_throw_exception(spl_ce_RuntimeException,
			"Not connected", 0);
		RETURN_THROWS();
	}

	if (type == SSL_STREAM_FLAG_UNI) {
		flags = SSL_STREAM_FLAG_UNI;
	} else if (type != SSL_STREAM_TYPE_BIDI) {
		zend_throw_exception(zend_ce_value_error,
			"Stream type must be QUIC_STREAM_BIDI or QUIC_STREAM_UNI", 0);
		RETURN_THROWS();
	}

	stream_ssl = SSL_new_stream(conn->ssl, flags);
	if (!stream_ssl) {
		quic_throw_ssl_error("Failed to create QUIC stream");
		RETURN_THROWS();
	}

	/* Create QuicStream object */
	object_init_ex(return_value, quic_stream_ce);
	stream = quic_stream_from_obj(Z_OBJ_P(return_value));
	stream->stream_ssl = stream_ssl;

	/* Reference the parent connection */
	stream->conn_zobj = Z_OBJ_P(ZEND_THIS);
	GC_ADDREF(stream->conn_zobj);
	conn->stream_count++;
	conn->streams_opened++;
}

/* ----------------------------------------------------------------
 * QuicConnection::acceptStream(float $timeout = 0.0): ?QuicStream
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicConnection, acceptStream)
{
	quic_connection_obj *conn;
	double timeout = 0.0;
	SSL *stream_ssl;
	quic_stream_obj *stream;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		Z_PARAM_DOUBLE(timeout)
	ZEND_PARSE_PARAMETERS_END();

	conn = Z_QUIC_CONNECTION_P(ZEND_THIS);

	if (!conn->connected || !conn->ssl) {
		zend_throw_exception(spl_ce_RuntimeException, "Not connected", 0);
		RETURN_THROWS();
	}

	/* Set incoming stream policy to accept */
	SSL_set_incoming_stream_policy(conn->ssl, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);

	/* Try to accept an incoming stream */
	stream_ssl = SSL_accept_stream(conn->ssl,
		(timeout > 0.0) ? SSL_ACCEPT_STREAM_NO_BLOCK : 0);

	if (!stream_ssl) {
		/* If timeout > 0, we could poll, but for simplicity we do a single non-blocking check.
		 * A more sophisticated implementation would use select/poll. */
		if (timeout > 0.0) {
			/* Set receive timeout */
			struct timeval tv;
			tv.tv_sec = (long)timeout;
			tv.tv_usec = (long)((timeout - (double)tv.tv_sec) * 1000000.0);
			setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

			stream_ssl = SSL_accept_stream(conn->ssl, 0);
		}

		if (!stream_ssl) {
			RETURN_NULL();
		}
	}

	/* Create QuicStream object */
	object_init_ex(return_value, quic_stream_ce);
	stream = quic_stream_from_obj(Z_OBJ_P(return_value));
	stream->stream_ssl = stream_ssl;

	stream->conn_zobj = Z_OBJ_P(ZEND_THIS);
	GC_ADDREF(stream->conn_zobj);
	conn->stream_count++;
	conn->streams_opened++;
}

/* ----------------------------------------------------------------
 * QuicStream::__construct() -- private, no direct instantiation
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicStream, __construct)
{
	zend_throw_exception(spl_ce_RuntimeException,
		"QuicStream cannot be instantiated directly. Use QuicConnection::openStream()", 0);
	RETURN_THROWS();
}

/* ----------------------------------------------------------------
 * QuicStream::write(string $data, int $flags = 0): int
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicStream, write)
{
	quic_stream_obj *stream;
	char *data;
	size_t data_len;
	zend_long flags = 0;
	int written;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STRING(data, data_len)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(flags)
	ZEND_PARSE_PARAMETERS_END();

	stream = Z_QUIC_STREAM_P(ZEND_THIS);

	if (!stream->stream_ssl) {
		zend_throw_exception(spl_ce_RuntimeException, "Stream is closed", 0);
		RETURN_THROWS();
	}

	/* If QUIC_WRITE_FLAG_CONCLUDE is set, write then conclude */
	written = SSL_write(stream->stream_ssl, data, (int)data_len);
	if (written <= 0) {
		int ssl_err = SSL_get_error(stream->stream_ssl, written);
		if (ssl_err == SSL_ERROR_ZERO_RETURN) {
			RETURN_LONG(0);
		}
		quic_throw_ssl_error("Stream write failed");
		RETURN_THROWS();
	}

	/* Track bytes sent */
	if (stream->conn_zobj) {
		quic_connection_obj *conn = quic_connection_from_obj(stream->conn_zobj);
		conn->bytes_sent += (uint64_t)written;
	}

	/* Send FIN if conclude flag set */
	if (flags & 1) { /* QUIC_WRITE_FLAG_CONCLUDE */
		SSL_stream_conclude(stream->stream_ssl, 0);
	}

	RETURN_LONG(written);
}

/* ----------------------------------------------------------------
 * QuicStream::read(int $length = 8192, float $timeout = -1.0): ?string
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicStream, read)
{
	quic_stream_obj *stream;
	zend_long length = 8192;
	double timeout = -1.0;
	char *buf;
	int bytes_read;

	ZEND_PARSE_PARAMETERS_START(0, 2)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(length)
		Z_PARAM_DOUBLE(timeout)
	ZEND_PARSE_PARAMETERS_END();

	stream = Z_QUIC_STREAM_P(ZEND_THIS);

	if (!stream->stream_ssl) {
		zend_throw_exception(spl_ce_RuntimeException, "Stream is closed", 0);
		RETURN_THROWS();
	}

	if (length < 1 || length > 16777216) {
		zend_throw_exception(zend_ce_value_error,
			"Length must be between 1 and 16777216", 0);
		RETURN_THROWS();
	}

	buf = emalloc((size_t)length);

	if (timeout >= 0.0 && stream->conn_zobj) {
		/* Non-blocking read with timeout using poll on the UDP socket */
		quic_connection_obj *conn = quic_connection_from_obj(stream->conn_zobj);

		/* Switch to non-blocking mode for timeout support */
		SSL_set_blocking_mode(conn->ssl, 0);

		struct timespec deadline;
		clock_gettime(CLOCK_MONOTONIC, &deadline);
		long timeout_us = (long)(timeout * 1000000.0);
		deadline.tv_sec += timeout_us / 1000000;
		deadline.tv_nsec += (timeout_us % 1000000) * 1000;
		if (deadline.tv_nsec >= 1000000000) {
			deadline.tv_sec++;
			deadline.tv_nsec -= 1000000000;
		}

		while (1) {
			/* Let OpenSSL process any pending QUIC events */
			SSL_handle_events(conn->ssl);

			bytes_read = SSL_read(stream->stream_ssl, buf, (int)length);
			if (bytes_read > 0) {
				/* Restore blocking mode */
				SSL_set_blocking_mode(conn->ssl, 1);
				goto read_success;
			}

			int ssl_err = SSL_get_error(stream->stream_ssl, bytes_read);
			if (ssl_err == SSL_ERROR_ZERO_RETURN) {
				SSL_set_blocking_mode(conn->ssl, 1);
				efree(buf);
				RETURN_NULL();
			}
			if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE) {
				SSL_set_blocking_mode(conn->ssl, 1);
				efree(buf);
				quic_throw_ssl_error("Stream read failed");
				RETURN_THROWS();
			}

			/* Check if we've exceeded the timeout */
			struct timespec now;
			clock_gettime(CLOCK_MONOTONIC, &now);
			if (now.tv_sec > deadline.tv_sec ||
				(now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
				SSL_set_blocking_mode(conn->ssl, 1);
				efree(buf);
				RETURN_NULL();
			}

			/* Poll on the UDP socket for a short interval */
			struct pollfd pfd;
			pfd.fd = conn->fd;
			pfd.events = POLLIN;
			long remaining_ms = (deadline.tv_sec - now.tv_sec) * 1000 +
				(deadline.tv_nsec - now.tv_nsec) / 1000000;
			if (remaining_ms < 1) remaining_ms = 1;
			if (remaining_ms > 50) remaining_ms = 50; /* poll in 50ms chunks */
			poll(&pfd, 1, (int)remaining_ms);
		}
	}

	/* Default: blocking read */
	bytes_read = SSL_read(stream->stream_ssl, buf, (int)length);

	if (bytes_read <= 0) {
		int ssl_err = SSL_get_error(stream->stream_ssl, bytes_read);
		efree(buf);

		if (ssl_err == SSL_ERROR_ZERO_RETURN) {
			/* Stream finished (FIN received) */
			RETURN_NULL();
		}
		if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
			/* Would block */
			RETURN_NULL();
		}

		quic_throw_ssl_error("Stream read failed");
		RETURN_THROWS();
	}

read_success:
	/* Track bytes received */
	if (stream->conn_zobj) {
		quic_connection_obj *conn = quic_connection_from_obj(stream->conn_zobj);
		conn->bytes_received += (uint64_t)bytes_read;
	}

	RETVAL_STRINGL(buf, bytes_read);
	efree(buf);
}

/* ----------------------------------------------------------------
 * QuicStream::conclude(): bool
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicStream, conclude)
{
	quic_stream_obj *stream;

	ZEND_PARSE_PARAMETERS_NONE();

	stream = Z_QUIC_STREAM_P(ZEND_THIS);

	if (!stream->stream_ssl) {
		zend_throw_exception(spl_ce_RuntimeException, "Stream is closed", 0);
		RETURN_THROWS();
	}

	RETURN_BOOL(SSL_stream_conclude(stream->stream_ssl, 0) == 1);
}

/* ----------------------------------------------------------------
 * QuicStream::reset(int $errorCode = 0): bool
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicStream, reset)
{
	quic_stream_obj *stream;
	zend_long error_code = 0;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(error_code)
	ZEND_PARSE_PARAMETERS_END();

	stream = Z_QUIC_STREAM_P(ZEND_THIS);

	if (!stream->stream_ssl) {
		zend_throw_exception(spl_ce_RuntimeException, "Stream is closed", 0);
		RETURN_THROWS();
	}

	SSL_STREAM_RESET_ARGS args = {0};
	args.quic_error_code = (uint64_t)error_code;

	RETURN_BOOL(SSL_stream_reset(stream->stream_ssl, &args, sizeof(args)) == 1);
}

/* ----------------------------------------------------------------
 * QuicStream::getId(): int
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicStream, getId)
{
	quic_stream_obj *stream;

	ZEND_PARSE_PARAMETERS_NONE();

	stream = Z_QUIC_STREAM_P(ZEND_THIS);

	if (!stream->stream_ssl) {
		zend_throw_exception(spl_ce_RuntimeException, "Stream is closed", 0);
		RETURN_THROWS();
	}

	RETURN_LONG((zend_long)SSL_get_stream_id(stream->stream_ssl));
}

/* ----------------------------------------------------------------
 * QuicStream::getType(): int
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicStream, getType)
{
	quic_stream_obj *stream;

	ZEND_PARSE_PARAMETERS_NONE();

	stream = Z_QUIC_STREAM_P(ZEND_THIS);

	if (!stream->stream_ssl) {
		zend_throw_exception(spl_ce_RuntimeException, "Stream is closed", 0);
		RETURN_THROWS();
	}

	RETURN_LONG((zend_long)SSL_get_stream_type(stream->stream_ssl));
}

/* ----------------------------------------------------------------
 * QuicStream::getReadState(): int
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicStream, getReadState)
{
	quic_stream_obj *stream;

	ZEND_PARSE_PARAMETERS_NONE();

	stream = Z_QUIC_STREAM_P(ZEND_THIS);

	if (!stream->stream_ssl) {
		RETURN_LONG(SSL_STREAM_STATE_NONE);
	}

	RETURN_LONG((zend_long)SSL_get_stream_read_state(stream->stream_ssl));
}

/* ----------------------------------------------------------------
 * QuicStream::getWriteState(): int
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicStream, getWriteState)
{
	quic_stream_obj *stream;

	ZEND_PARSE_PARAMETERS_NONE();

	stream = Z_QUIC_STREAM_P(ZEND_THIS);

	if (!stream->stream_ssl) {
		RETURN_LONG(SSL_STREAM_STATE_NONE);
	}

	RETURN_LONG((zend_long)SSL_get_stream_write_state(stream->stream_ssl));
}

/* ----------------------------------------------------------------
 * QuicStream::isReadable(): bool
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicStream, isReadable)
{
	quic_stream_obj *stream;

	ZEND_PARSE_PARAMETERS_NONE();

	stream = Z_QUIC_STREAM_P(ZEND_THIS);

	if (!stream->stream_ssl) {
		RETURN_FALSE;
	}

	int state = SSL_get_stream_read_state(stream->stream_ssl);
	RETURN_BOOL(state == SSL_STREAM_STATE_OK);
}

/* ----------------------------------------------------------------
 * QuicStream::isWritable(): bool
 * ---------------------------------------------------------------- */

PHP_METHOD(QuicStream, isWritable)
{
	quic_stream_obj *stream;

	ZEND_PARSE_PARAMETERS_NONE();

	stream = Z_QUIC_STREAM_P(ZEND_THIS);

	if (!stream->stream_ssl) {
		RETURN_FALSE;
	}

	int state = SSL_get_stream_write_state(stream->stream_ssl);
	RETURN_BOOL(state == SSL_STREAM_STATE_OK);
}

/* ----------------------------------------------------------------
 * quic_connect(string $host, int $port, array $options = []): QuicConnection
 * ---------------------------------------------------------------- */

PHP_FUNCTION(quic_connect)
{
	char *host;
	size_t host_len;
	zend_long port;
	zval *options = NULL;
	zval conn_obj;
	zval func_name, retval;
	zval construct_args[3];

	ZEND_PARSE_PARAMETERS_START(2, 3)
		Z_PARAM_STRING(host, host_len)
		Z_PARAM_LONG(port)
		Z_PARAM_OPTIONAL
		Z_PARAM_ARRAY(options)
	ZEND_PARSE_PARAMETERS_END();

	/* Create QuicConnection object */
	object_init_ex(&conn_obj, quic_connection_ce);

	/* Call __construct */
	ZVAL_STRING(&construct_args[0], host);
	ZVAL_LONG(&construct_args[1], port);
	if (options) {
		ZVAL_COPY(&construct_args[2], options);
	}

	ZVAL_STRING(&func_name, "__construct");
	if (call_user_function(NULL, &conn_obj, &func_name, &retval,
			options ? 3 : 2, construct_args) == FAILURE) {
		zval_ptr_dtor(&func_name);
		zval_ptr_dtor(&construct_args[0]);
		if (options) {
			zval_ptr_dtor(&construct_args[2]);
		}
		zval_ptr_dtor(&conn_obj);
		zend_throw_exception(spl_ce_RuntimeException,
			"Failed to construct QuicConnection", 0);
		RETURN_THROWS();
	}

	zval_ptr_dtor(&func_name);
	zval_ptr_dtor(&construct_args[0]);
	if (options) {
		zval_ptr_dtor(&construct_args[2]);
	}
	zval_ptr_dtor(&retval);

	if (EG(exception)) {
		zval_ptr_dtor(&conn_obj);
		RETURN_THROWS();
	}

	/* Call connect() */
	ZVAL_STRING(&func_name, "connect");
	if (call_user_function(NULL, &conn_obj, &func_name, &retval, 0, NULL) == FAILURE) {
		zval_ptr_dtor(&func_name);
		zval_ptr_dtor(&conn_obj);
		zend_throw_exception(spl_ce_RuntimeException,
			"Failed to connect", 0);
		RETURN_THROWS();
	}

	zval_ptr_dtor(&func_name);
	zval_ptr_dtor(&retval);

	if (EG(exception)) {
		zval_ptr_dtor(&conn_obj);
		RETURN_THROWS();
	}

	RETURN_ZVAL(&conn_obj, 0, 0);
}

/* ----------------------------------------------------------------
 * Arginfo
 * ---------------------------------------------------------------- */

/* QuicConnection */
ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_connection_construct, 0, 0, 2)
	ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, port, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_connection_connect, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_quic_connection_open_stream, 0, 0, QuicStream, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, type, IS_LONG, 0, "QUIC_STREAM_BIDI")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_quic_connection_accept_stream, 0, 0, QuicStream, 1)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, timeout, IS_DOUBLE, 0, "0.0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_connection_close, 0, 0, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, errorCode, IS_LONG, 0, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, reason, IS_STRING, 0, "\"\"")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_connection_is_connected, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_connection_get_alpn, 0, 0, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_connection_get_peer_cert, 0, 0, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_connection_get_stats, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

/* QuicStream */
ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_stream_construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_stream_write, 0, 1, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_stream_read, 0, 0, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, length, IS_LONG, 0, "8192")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, timeout, IS_DOUBLE, 0, "-1.0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_stream_conclude, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_stream_reset, 0, 0, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, errorCode, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_stream_get_id, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_stream_get_type, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_stream_get_read_state, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_stream_get_write_state, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_stream_is_readable, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_stream_is_writable, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

/* quic_connect function */
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_quic_connect, 0, 2, QuicConnection, 0)
	ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, port, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

/* ----------------------------------------------------------------
 * Method/function tables
 * ---------------------------------------------------------------- */

static const zend_function_entry quic_connection_methods[] = {
	PHP_ME(QuicConnection, __construct, arginfo_quic_connection_construct, ZEND_ACC_PUBLIC)
	PHP_ME(QuicConnection, connect, arginfo_quic_connection_connect, ZEND_ACC_PUBLIC)
	PHP_ME(QuicConnection, openStream, arginfo_quic_connection_open_stream, ZEND_ACC_PUBLIC)
	PHP_ME(QuicConnection, acceptStream, arginfo_quic_connection_accept_stream, ZEND_ACC_PUBLIC)
	PHP_ME(QuicConnection, close, arginfo_quic_connection_close, ZEND_ACC_PUBLIC)
	PHP_ME(QuicConnection, isConnected, arginfo_quic_connection_is_connected, ZEND_ACC_PUBLIC)
	PHP_ME(QuicConnection, getAlpn, arginfo_quic_connection_get_alpn, ZEND_ACC_PUBLIC)
	PHP_ME(QuicConnection, getPeerCertificate, arginfo_quic_connection_get_peer_cert, ZEND_ACC_PUBLIC)
	PHP_ME(QuicConnection, getStats, arginfo_quic_connection_get_stats, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

static const zend_function_entry quic_stream_methods[] = {
	PHP_ME(QuicStream, __construct, arginfo_quic_stream_construct, ZEND_ACC_PRIVATE)
	PHP_ME(QuicStream, write, arginfo_quic_stream_write, ZEND_ACC_PUBLIC)
	PHP_ME(QuicStream, read, arginfo_quic_stream_read, ZEND_ACC_PUBLIC)
	PHP_ME(QuicStream, conclude, arginfo_quic_stream_conclude, ZEND_ACC_PUBLIC)
	PHP_ME(QuicStream, reset, arginfo_quic_stream_reset, ZEND_ACC_PUBLIC)
	PHP_ME(QuicStream, getId, arginfo_quic_stream_get_id, ZEND_ACC_PUBLIC)
	PHP_ME(QuicStream, getType, arginfo_quic_stream_get_type, ZEND_ACC_PUBLIC)
	PHP_ME(QuicStream, getReadState, arginfo_quic_stream_get_read_state, ZEND_ACC_PUBLIC)
	PHP_ME(QuicStream, getWriteState, arginfo_quic_stream_get_write_state, ZEND_ACC_PUBLIC)
	PHP_ME(QuicStream, isReadable, arginfo_quic_stream_is_readable, ZEND_ACC_PUBLIC)
	PHP_ME(QuicStream, isWritable, arginfo_quic_stream_is_writable, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

static const zend_function_entry quic_functions[] = {
	PHP_FE(quic_connect, arginfo_quic_connect)
	PHP_FE_END
};

/* ----------------------------------------------------------------
 * Module lifecycle
 * ---------------------------------------------------------------- */

PHP_MINIT_FUNCTION(quic)
{
	zend_class_entry ce;

	/* Register QuicConnection class */
	INIT_CLASS_ENTRY(ce, "QuicConnection", quic_connection_methods);
	quic_connection_ce = zend_register_internal_class(&ce);
	quic_connection_ce->create_object = quic_connection_create;
	quic_connection_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_NO_DYNAMIC_PROPERTIES;

	memcpy(&quic_connection_handlers, &std_object_handlers, sizeof(zend_object_handlers));
	quic_connection_handlers.offset = XtOffsetOf(quic_connection_obj, std);
	quic_connection_handlers.free_obj = quic_connection_free;
	quic_connection_handlers.clone_obj = NULL;

	/* Register QuicStream class */
	INIT_CLASS_ENTRY(ce, "QuicStream", quic_stream_methods);
	quic_stream_ce = zend_register_internal_class(&ce);
	quic_stream_ce->create_object = quic_stream_create;
	quic_stream_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_NO_DYNAMIC_PROPERTIES;

	memcpy(&quic_stream_handlers, &std_object_handlers, sizeof(zend_object_handlers));
	quic_stream_handlers.offset = XtOffsetOf(quic_stream_obj, std);
	quic_stream_handlers.free_obj = quic_stream_free;
	quic_stream_handlers.clone_obj = NULL;

	/* Register constants */
	REGISTER_LONG_CONSTANT("QUIC_STREAM_BIDI", SSL_STREAM_TYPE_BIDI, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("QUIC_STREAM_UNI", SSL_STREAM_FLAG_UNI, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("QUIC_STREAM_STATE_NONE", SSL_STREAM_STATE_NONE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("QUIC_STREAM_STATE_OK", SSL_STREAM_STATE_OK, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("QUIC_STREAM_STATE_FINISHED", SSL_STREAM_STATE_FINISHED, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("QUIC_STREAM_STATE_RESET_LOCAL", SSL_STREAM_STATE_RESET_LOCAL, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("QUIC_STREAM_STATE_RESET_REMOTE", SSL_STREAM_STATE_RESET_REMOTE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("QUIC_STREAM_STATE_CONN_CLOSED", SSL_STREAM_STATE_CONN_CLOSED, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("QUIC_WRITE_FLAG_CONCLUDE", 1, CONST_CS | CONST_PERSISTENT);

	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(quic)
{
	if (socks5_bio_method) {
		BIO_meth_free(socks5_bio_method);
		socks5_bio_method = NULL;
	}
	return SUCCESS;
}

PHP_MINFO_FUNCTION(quic)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "quic support", "enabled");
	php_info_print_table_row(2, "Version", PHP_QUIC_VERSION);
	php_info_print_table_row(2, "Backend", "OpenSSL QUIC");
	php_info_print_table_row(2, "OpenSSL version", OPENSSL_VERSION_TEXT);
	php_info_print_table_row(2, "Mode", "Client only (OpenSSL 3.2+)");
	php_info_print_table_end();
}

zend_module_entry quic_module_entry = {
	STANDARD_MODULE_HEADER,
	"quic",
	quic_functions,
	PHP_MINIT(quic),
	PHP_MSHUTDOWN(quic),
	NULL, /* RINIT */
	NULL, /* RSHUTDOWN */
	PHP_MINFO(quic),
	PHP_QUIC_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_QUIC
ZEND_GET_MODULE(quic)
#endif
