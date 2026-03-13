dnl config.m4 for extension quic

PHP_ARG_ENABLE([quic],
  [whether to enable quic support],
  [AS_HELP_STRING([--enable-quic],
    [Enable quic support])],
  [no])

if test "$PHP_QUIC" != "no"; then
  dnl Check for OpenSSL QUIC support (requires OpenSSL 3.2+)
  AC_CHECK_HEADER([openssl/quic.h], [],
    [AC_MSG_ERROR([OpenSSL 3.2+ with QUIC support required. Install openssl-devel.])])

  PHP_CHECK_LIBRARY(ssl, OSSL_QUIC_client_method,
    [PHP_ADD_LIBRARY(ssl, 1, QUIC_SHARED_LIBADD)
     PHP_ADD_LIBRARY(crypto, 1, QUIC_SHARED_LIBADD)],
    [AC_MSG_ERROR([OpenSSL QUIC support not found. Requires OpenSSL 3.2+.])])

  PHP_SUBST(QUIC_SHARED_LIBADD)
  PHP_NEW_EXTENSION(quic, quic.c, $ext_shared)
fi
