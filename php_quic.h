#ifndef PHP_QUIC_H
#define PHP_QUIC_H

extern zend_module_entry quic_module_entry;
#define phpext_quic_ptr &quic_module_entry

#define PHP_QUIC_VERSION "1.2.0"

#ifdef PHP_WIN32
# define PHP_QUIC_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
# define PHP_QUIC_API __attribute__ ((visibility("default")))
#else
# define PHP_QUIC_API
#endif

PHP_MINIT_FUNCTION(quic);
PHP_MSHUTDOWN_FUNCTION(quic);
PHP_MINFO_FUNCTION(quic);

#endif /* PHP_QUIC_H */
