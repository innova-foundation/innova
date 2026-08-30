/* Platform dispatch for the vendored Tor configuration header.
   Innova has no ./configure step for tor; orconfig_<platform>.h is the output of
   running the upstream configure once per platform. See VERSION for the exact
   configure line and how to regenerate. */

#ifndef GENERIC_ORCONFIG_H_
#define GENERIC_ORCONFIG_H_

#if _WIN32 || _WIN64
#error "Windows orconfig has not been regenerated for tor-0.4.8.25; see src/tor/VERSION."
#elif defined(__darwin__) || defined(__APPLE__)
#include "orconfig_apple.h"
#else
#include "orconfig_linux.h"
#endif

/* Normally passed by upstream's configure. Read only by config.c (geoip paths,
   default-datadir fallback) and inert here: the datadir is passed on argv. */
#ifndef SHARE_DATADIR
#define SHARE_DATADIR "/usr/local/share"
#endif
#ifndef LOCALSTATEDIR
#define LOCALSTATEDIR "/usr/local/var"
#endif
#ifndef BINDIR
#define BINDIR "/usr/local/bin"
#endif

#endif  // GENERIC_ORCONFIG_H_
