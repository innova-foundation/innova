#ifndef GENERIC_ORCONFIG_H_
#define GENERIC_ORCONFIG_H_

#if _WIN32 || _WIN64
#if _WIN64
#include "orconfig_win64.h"
#else
#include "orconfig_win32.h"
#endif
#elif defined(__darwin__) || defined(__APPLE__)
#include "orconfig_apple.h"
#else
#include "orconfig_linux.h"
#endif


/* The platform orconfig values were generated against the OpenSSL 1.0.x API,
   where these accessors did not exist and SSL/SSL_SESSION were public structs.
   1.1.0 provides them and makes the structs opaque, so set them from the
   library version rather than the generated probe. */
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#ifndef HAVE_SSL_GET_CLIENT_CIPHERS
#define HAVE_SSL_GET_CLIENT_CIPHERS 1
#endif
#ifndef HAVE_SSL_SESSION_GET_MASTER_KEY
#define HAVE_SSL_SESSION_GET_MASTER_KEY 1
#endif
#ifndef HAVE_SSL_GET_CLIENT_RANDOM
#define HAVE_SSL_GET_CLIENT_RANDOM 1
#endif
#ifndef HAVE_SSL_GET_SERVER_RANDOM
#define HAVE_SSL_GET_SERVER_RANDOM 1
#endif
#endif

#endif  // GENERIC_ORCONFIG_H_
