dnl Process this file with autoconf to produce a configure script.
dnl
dnl There are a couple of environment defined variables which this script
dnl makes use of in addition to the standard CXXFLAGS/LDFLAGS/etc. These are:
dnl
dnl RELEASE_TAG        - Debian release tag which is put to debian/changelog
dnl


AC_CONFIG_SRCDIR([zorp/main.cc])
AC_INIT([zorp], m4_esyscmd([tr -d '\n' < VERSION]))
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_MACRO_DIR([m4])

dnl ***************************************************************************
dnl Definitions

ZORP_PRODUCT_NAME="Zorp Professional"

dnl ***************************************************************************
dnl Dependencies

GLIB_MIN_VERSION="2.32.0"
OPENSSL_MIN_VERSION=1.1.1
OPENSSL_MAX_VERSION=1.1.2
PYTHON_MIN_VERSION="2.7"
PYTHON_MAX_VERSION="2.8"
m4_define_default([_AM_PYTHON_INTERPRETER_LIST], [python2.7])

dnl ***************************************************************************
dnl Initial setup

# We want an absolute path to the source-dir.
case "$srcdir" in
    /*)
        top_srcdir=$srcdir
        ;;
    *)
        oldsrcdir="$srcdir"
        top_srcdir="`cd \"$srcdir\"; pwd`"
        ;;
esac

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])
if test -z "$RELEASE_TAG"; then
        RELEASE_TAG=release
fi

AM_CONFIG_HEADER(lib/zorp/zorpconfig.h)
AC_PREFIX_DEFAULT(/usr/local)

zorp_srcdir=$top_srcdir

AC_ARG_ENABLE(trace,
              [  --enable-trace       Enable debug information & messages (default: no)],,
              enable_trace=no)

AC_ARG_ENABLE(werror,
              [  --enable-werror      When enabled, consider compiler warnings as errors (default: yes)],,
              enable_werror=yes)

AC_ARG_ENABLE(coverage,
              [  --enable-coverage    Enable runtime coverage information generation (default: no)],,
              enable_coverage=no)

AC_ARG_ENABLE(ip_options,
              [  --enable-ip-options  Enable handling IP options (EXPERIMENTAL)],,
              enable_ip_options=no)

AC_ARG_ENABLE(ipv6,
              [  --enable-ipv6        Enable IPv6 support (EXPERIMENTAL)],,
              enable_ipv6=yes)

AC_ARG_ENABLE(prefork,
              [  --enable-prefork             Enable prefork],,
	      enable_prefork=no)

AC_ARG_ENABLE(predictable_random,
              [  --enable-predictable-random             Enable predictable random],,
        enable_predictable_random=no)

AC_ARG_ENABLE(kzorp,
              [  --enable-kzorp       Enable kzorp],,
	      enable_kzorp=yes)

ZORP_MUNIN_CONF_DIR="${sysconfdir}/munin/plugin-conf.d"
ZORP_NAGIOS_CONF_DIR="${sysconfdir}/nagios/nrpe.d"
ZORP_SUDOERSD_CONF_DIR="${sysconfdir}/sudoers.d"

dnl Library versioning, the resulting shared object is named:
dnl 	zorplib-<RELEASE>.so.<AGE>
dnl
VERSION_NOSNAPSHOT="`echo $VERSION | cut -d '+' -f 1 | cut -d '~' -f 1`"

VERSION_MAJOR=`echo $VERSION_NOSNAPSHOT |  cut -d '.' -f 1`
VERSION_MINOR=`echo $VERSION_NOSNAPSHOT |  cut -d '.' -f 2`
VERSION_COMPAT=`echo $VERSION_NOSNAPSHOT |  cut -d '.' -f 3`

NEXT_VERSION_MAJOR=$(($VERSION_MAJOR + 1))

ZORPLL_MIN_VERSION_MICRO="7"
ZORPLL_MIN_VERSION="$VERSION_MAJOR.$VERSION_MINOR.$ZORPLL_MIN_VERSION_MICRO"

LIBZORP_LT_RELEASE="$VERSION_MAJOR.$VERSION_MINOR"
LIBZORP_LT_COMPAT_BRANCH="$VERSION_MAJOR.$VERSION_MINOR-$VERSION_COMPAT"
LIBZORP_LT_COMPAT_PL="$VERSION_COMPAT"


ZORPLIC_MIN_VERSION_MICRO="7"
ZORPLIC_MIN_VERSION="$VERSION_MAJOR.$VERSION_MINOR.$ZORPLIC_MIN_VERSION_MICRO"

ZORPMISC_MIN_VERSION_MICRO="7"
ZORPMISC_MIN_VERSION="$VERSION_MAJOR.$VERSION_MINOR.$ZORPMISC_MIN_VERSION_MICRO"


ZORP_MIN_VERSION_MICRO="7"
ZORP_MIN_VERSION="$VERSION_MAJOR.$VERSION_MINOR.$ZORP_MIN_VERSION_MICRO"

dnl ***************************************************************************
dnl Checks for programs.

AC_PROG_CXX
AC_PROG_CXXCPP

AC_PROG_MKDIR_P

AX_CXX_COMPILE_STDCXX_17([noext], [mandatory])
AX_CXX_MIN_VERSION_CHECK
AC_DISABLE_STATIC

AC_LANG(C++)

AM_PROG_LIBTOOL
AC_PATH_PROG(GPERF, gperf)
if test "x$GPERF" = "x"; then
	AC_ERROR(No gperf found)
fi

dnl ***************************************************************************
dnl Checks for header files.


AC_CHECK_HEADERS(sys/capability.h sys/prctl.h sys/syscall.h limits.h stdbool.h stdint.h)
AC_CHECK_HEADERS([sys/thr.h])
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([linux/netlink.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_CACHE_CHECK(for MSG_PROXY, blb_cv_msg_proxy,
  [AC_EGREP_CPP(MSG_PROXY,
[
#include <sys/types.h>
#include <sys/socket.h>

#ifdef MSG_PROXY
MSG_PROXY
#endif
],
  blb_cv_msg_proxy=yes,
  blb_cv_msg_proxy=no)])

if test "x$blb_cv_msg_proxy" = "xyes"; then
	AC_DEFINE(HAVE_MSG_PROXY, 1, [Have MSG_PROXY flag (Linux 2.2)])
fi

dnl ***************************************************************************
dnl Checks for libraries.

dnl Checks for library functions.
AC_CHECK_LIB(socket, setsockopt, SOCK_LIBS="$SOCK_LIBS -lsocket")
AC_CHECK_LIB(xnet, inet_addr, SOCK_LIBS="$SOCK_LIBS -lxnet")
AC_CHECK_LIB(nsl, gethostbyname, SOCK_LIBS="$SOCK_LIBS -lnsl")

dnl Python might required -ldl, -lutil & -lm
AC_CHECK_LIB(rt, aio_read, PYTHON_DEPS="$PYTHON_DEPS -lrt")
AC_CHECK_LIB(m, sin, PYTHON_DEPS="$PYTHON_DEPS -lm")
AC_CHECK_LIB(util, openpty, PYTHON_DEPS="$PYTHON_DEPS -lutil")
AC_CHECK_LIB(dl, dlsym, PYTHON_DEPS="$PYTHON_DEPS -ldl")

AC_CHECK_LIB(z, inflate, ZLIB_LIBS="$ZLIB_LIBS -lz")

AC_CHECK_FUNCS(socket,,AC_MSG_ERROR(Cannot find socket in C library))
AC_CHECK_FUNCS(select snprintf vsnprintf strerror inet_aton)
AC_CHECK_FUNCS(prctl gethostbyname_r)

AC_CACHE_CHECK(for PR_SET_DUMPABLE, blb_cv_dumpable,
  [AC_EGREP_CPP(PR_SET_DUMPABLE,
[
#include <sys/prctl.h>

PR_SET_DUMPABLE
],
  blb_cv_dumpable=no,
  blb_cv_dumpable=yes)])

if test "x$blb_cv_dumpable" = "xyes"; then
        AC_DEFINE(HAVE_PR_SET_DUMPABLE, 1, [Zorp may enable core_dumping Linux 2.4-])
fi

AM_PATH_PYTHON([$PYTHON_MIN_VERSION],,)
AM_CONDITIONAL([PYTHON_VERSION_MATCHES], [test "x$PYTHON_VERSION" = "x$PYTHON_MIN_VERSION"])
AM_COND_IF([PYTHON_VERSION_MATCHES],, AC_MSG_ERROR(Cannot find Python version = $PYTHON_MIN_VERSION))

AC_CHECK_DECLS([IP_FREEBIND], [], [], [[#include <linux/in.h>]])
AC_CHECK_DECLS([IP_TRANSPARENT], [], [], [[#include <linux/in.h>]])
AC_CHECK_DECLS([IPV6_TRANSPARENT], [], [], [[#include <linux/in6.h>]])

AC_CHECK_DECLS([IP_BINDANY], [], [], [#include <netinet/in.h>])
AC_CHECK_DECLS([IPV6_BINDANY], [], [], [[#include <netinet6/in6.h>]])

AC_CHECK_DECLS([TCP_CORK], [], [], [[#include <linux/tcp.h>]])
AC_CHECK_DECLS([TCP_NOPUSH], [], [], [[#include <netinet/tcp.h>]])

PKG_CHECK_MODULES(GLIB, glib-2.0 >= $GLIB_MIN_VERSION,,
	AC_MSG_ERROR(Cannot find GLib library version >= $GLIB_MIN_VERSION: is pkg-config in path?))

PKG_CHECK_MODULES(GMODULE, gmodule-2.0 >= $GLIB_MIN_VERSION,,
	AC_MSG_ERROR(Cannot find GModule library version >= $GLIB_MIN_VERSION: is pkg-config in path?))

PKG_CHECK_MODULES(GTHREAD, gthread-2.0 >= $GLIB_MIN_VERSION,,
	AC_MSG_ERROR(Cannot find GThread library version >= $GLIB_MIN_VERSION: is pkg-config in path?))

PKG_CHECK_MODULES(ZORPLL, zorpll-${LIBZORP_LT_RELEASE} >= $ZORPLL_MIN_VERSION,,
	AC_MSG_ERROR(Cannot find ZORP Lowlevel library version >= $ZORPLL_MIN_VERSION: is pkg-config in path?))

PKG_CHECK_MODULES(OPENSSL, [openssl >= $OPENSSL_MIN_VERSION openssl < $OPENSSL_MAX_VERSION],,
        AC_MSG_ERROR(Cannot find OpenSSL library $OPENSSL_MIN_VERSION <= version < $OPENSSL_MAX_VERSION: is pkg-config in path?))


PKG_CHECK_MODULES(PYTHON, python-2.7 >= $PYTHON_MIN_VERSION,,
	AC_MSG_ERROR(Cannot find Python library version >= $PYTHON_MIN_VERSION: is pkg-config in path?))
PKG_CHECK_MODULES(PYTHON, python-2.7 < $PYTHON_MAX_VERSION,,
	AC_MSG_ERROR(Cannot find Python library version >= $PYTHON_MAX_VERSION: is pkg-config in path?))




AM_CONDITIONAL(ENABLE_KZORP, test x$enable_kzorp = xyes)

if test "x$ac_cv_func_gethostbyname_r" = "xyes"; then
dnl	if test "`uname -s`" = "Linux"; then
dnl		AC_DEFINE(HAVE_LEAK_IN_GETHOSTBYNAME_R, 1, [We have a leak in gethostbyname_r, avoid using it])
	if test "`uname -s`" = "SunOS"; then
		AC_DEFINE(HAVE_SUN_GETHOSTBYNAME_R, 1, [We have a Solaris style gethostbyname_r];)
	fi
fi

dnl ***************************************************************************
dnl Misc checks

AC_SYS_LARGEFILE

CURRDATE=`date -R`

PRODUCT_DEFS_CXXFLAGS="-DBROCHURE_VERSION=\\\"7\\\" -DGATEWAY_PRODUCT_NAME=\\\"Zorp\\ GPL\\\""

dnl ***************************************************************************
dnl Export detected settings to Makefiles and Zorp

AC_SUBST(zorp_srcdir)
AC_SUBST(ZORP_MUNIN_CONF_DIR)
AC_SUBST(ZORP_NAGIOS_CONF_DIR)
AC_SUBST(ZORP_PYTHON_DIR)
AC_SUBST(ZORPCTL_PYTHON_DIR)
AC_SUBST(ZORP_SUDOERSD_CONF_DIR)
AC_SUBST(ENABLE_KZORP)

ZORP_MUNIN_DIR="${prefix}/share/munin/plugins"
ZORP_NAGIOS_DIR="${prefix}/lib/nagios/plugins"
ZORP_PYTHON_DIR="${pythondir}/Zorp"
ZORPCTL_PYTHON_DIR="${pythondir}/zorpctl"

ZORP_SYSCONFDIR="${sysconfdir}/zorp"
ZORP_DATADIR="${datadir}/zorp"
ZORP_LIBDIR="${libdir}/zorp"
ZORP_SBINDIR="${sbindir}"
ZORP_STATEDIR="${localstatedir}/lib/zorp"
ZORP_PIDFILEDIR="${localstatedir}/run/zorp/"
LIBDIR="${libdir}"

dnl ***************************************************************************
dnl Export results

enable_value()
{
	if test "x$1" = "xyes" ; then
		echo 1
	else
		echo 0
	fi
}

dnl ***************************************************************************
dnl Size check of pointers
AC_CHECK_SIZEOF(void *)

AC_SUBST(RELEASE_TAG)
AC_SUBST(BROCHURE_VERSION)

AC_SUBST(ZORP_PACKAGE_LICENSE)
AC_SUBST(PACKAGE_SUFFIX)

AC_DEFINE_UNQUOTED(ZORP_PRODUCT_NAME, "$ZORP_PRODUCT_NAME", [Required product name in license])
AC_SUBST(ZORP_PRODUCT_NAME)

AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Zorp package version])
AC_DEFINE_UNQUOTED(ZORP_SOURCE_REVISION, "$SOURCE_REVISION", [Zorp source revision number])

AC_DEFINE_UNQUOTED(ENABLE_TRACE, `enable_value $enable_trace`, [Enable trace messages])
AC_DEFINE_UNQUOTED(ENABLE_IPOPTIONS, `enable_value $enable_ip_options`, [Enable IP option processing])
AC_DEFINE_UNQUOTED(ENABLE_IPV6, `enable_value $enable_ipv6`, [Enable IPv6 support])
AC_DEFINE_UNQUOTED(ENABLE_PREFORK, `enable_value $enable_prefork`, [Enable prefork support])
AC_DEFINE_UNQUOTED(ENABLE_KZORP, `enable_value $enable_kzorp`, [Enable kzorp support])

WARNING_CXXFLAGS="-Wall -W -Werror-implicit-function-declaration -Wwrite-strings"
DIRECTORY_CXXFLAGS="-DZORP_PIDFILEDIR=\\\"${ZORP_PIDFILEDIR}\\\" -DZORP_STATEDIR=\\\"${ZORP_STATEDIR}\\\" -DZORP_SBINDIR=\\\"${ZORP_SBINDIR}\\\" -DZORP_SYSCONFDIR=\\\"${ZORP_SYSCONFDIR}\\\" -DZORP_DATADIR=\\\"${ZORP_DATADIR}\\\" -DZORP_LIBDIR=\\\"${ZORP_LIBDIR}\\\" -DLIBDIR=\\\"${LIBDIR}\\\""

if test "x$enable_coverage" = "xyes"; then
        COVERAGE_CXXFLAGS="-fprofile-arcs -ftest-coverage"
        COVERAGE_LIBS="-fprofile-arcs -lgcov"
fi

GENERAL_CXXFLAGS="$PRODUCT_DEFS_CXXFLAGS -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -I$top_srcdir/lib $COVERAGE_CXXFLAGS $WARNING_CXXFLAGS $DIRECTORY_CXXFLAGS"

# Dependencies outside the source tree
DEPS_CXXFLAGS="$PRODUCT_DEFS_CFLAGS $ZORPLL_CFLAGS $ZORPLIC_CFLAGS $ZORPMISC_CFLAGS $PYTHON_CFLAGS $OPENSSL_CFLAGS"
DEPS_LIBS="$ZORPLL_LIBS $ZORPLIC_LIBS $ZORPMISC_LIBS $PYTHON_LIBS $PYTHON_DEPS $COREDUMP_LIBS $OPENSSL_LIBS"
# zorp library libs
LIBZORP_CXXFLAGS="$GENERAL_CXXFLAGS $DEPS_CXXFLAGS $GLIB_CXXFLAGS $GMODULE_CXXFLAGS $GTHREAD_CXXFLAGS $PYTHON_CXXFLAGS $OPENSSL_CXXFLAGS $PCAP_CXXFLAGS"
LIBZORP_LIBS="$DEPS_LIBS $GLIB_LIBS $GMODULE_LIBS $GTHREAD_LIBS $PYTHON_LIBS $OPENSSL_LIBS $PCAP_LIBS"
# Zorp main program
ZORP_CXXFLAGS="$GENERAL_CXXFLAGS $DEPS_CXXFLAGS"
ZORP_LIBS="-L\$(top_builddir)/lib/ -lzorp $DEPS_LIBS $LIBZORP_LIBS"
# zorpctl program
ZORPCTL_CXXFLAGS="$GENERAL_CXXFLAGS $GLIB_CFLAGS $SOCK_CFLAGS $ZORPLL_CFLAGS"
ZORPCTL_LIBS="$GLIB_LIBS $SOCK_LIBS"
# zorp modules
MODULES_CXXFLAGS="-I$top_srcdir/libproxy/ $GENERAL_CXXFLAGS $DEPS_CXXFLAGS"
MODULES_LIBS="-L\$(top_builddir)/lib/ -lzorp -L\$(top_builddir)/libproxy/ -lzorpproxy $DEPS_LIBS"
# module test program
MODULETESTS_CXXFLAGS="$MODULES_CXXFLAGS $ZORP_CXXFLAGS"
MODULETESTS_LIBS="$MODULES_LIBS $ZORP_LIBS"
# unit test program
UNITTESTS_CXXFLAGS="$MODULES_CXXFLAGS $ZORP_CXXFLAGS"
UNITTESTS_LIBS="$MODULES_LIBS $ZORP_LIBS"

AC_SUBST(LIBZORP_CXXFLAGS)
AC_SUBST(LIBZORP_LIBS)
AC_SUBST(ZORP_CXXFLAGS)
AC_SUBST(ZORP_LIBS)
AC_SUBST(ZORPCTL_CXXFLAGS)
AC_SUBST(ZORPCTL_LIBS)
AC_SUBST(MODULES_CXXFLAGS)
AC_SUBST(MODULES_LIBS)
AC_SUBST(MODULETESTS_CXXFLAGS)
AC_SUBST(MODULETESTS_LIBS)
AC_SUBST(UNITTESTS_CXXFLAGS)
AC_SUBST(UNITTESTS_LIBS)

if test "x$enable_predictable_random" = "xyes"; then
        AC_DEFINE(PREDICTABLE_RANDOM_ENABLED, 1, [Predictable random is enabled])
fi


AC_SUBST(ZORP_MUNIN_DIR)
AC_SUBST(ZORP_NAGIOS_DIR)

AC_SUBST(ZORP_DATADIR)
AC_SUBST(ZORP_LIBDIR)
AC_SUBST(ZORP_PIDFILEDIR)
AC_SUBST(ZORP_SYSCONFDIR)
AC_SUBST(ZORP_STATEDIR)
AC_SUBST(ZORP_SBINDIR)

date=`date +%Y/%m/%d`
AC_DEFINE_UNQUOTED(ZORP_CONFIG_DATE, "$date", [Configuration date])

cat <<EOF


Compile time options:
---------------------
coverage: $enable_coverage
ipoptions: $enable_ip_options
ipv6: $enable_ipv6
prefork: $enable_prefork
kzorp: $enable_kzorp
License: $ZORP_PACKAGE_LICENSE


EOF

AC_SUBST(LIBZORP_LT_RELEASE)
AC_SUBST(LIBZORP_LT_COMPAT_BRANCH)
AC_SUBST(LIBZORP_LT_COMPAT_PL)

AC_SUBST(GLIB_MIN_VERSION)
AC_SUBST(ZORPLL_MIN_VERSION)
AC_SUBST(ZORPLIC_MIN_VERSION)
AC_SUBST(ZORPMISC_MIN_VERSION)
AC_SUBST(OPENSSL_MIN_VERSION)
AC_SUBST(PYTHON_MIN_VERSION)
AC_SUBST(ZORP_MIN_VERSION)
AC_SUBST(CURRDATE)
AC_SUBST(VERSION_MAJOR)
AC_SUBST(NEXT_VERSION_MAJOR)

AC_CONFIG_LINKS([pylib/Zorp/__init__.py:pylib/Zorp/__init__.py])

AC_CONFIG_FILES([
Makefile
doc/Makefile
doc/man/Makefile
doc/man/zorp-entities.ent
lib/Makefile
lib/zorp/Makefile
libproxy/Makefile
libproxy/zorp/Makefile
libproxy/zorp/proxy/Makefile
libzorp.pc
libzorpproxy.pc
moduledist.conf
modules/Makefile
modules/anypy/Makefile
modules/apr/Makefile
modules/finger/Makefile
modules/ftp/Makefile
modules/ftp/tests/Makefile
modules/http/Makefile
modules/http/messages/Makefile
modules/http/messages/de/Makefile
modules/http/messages/en/Makefile
modules/http/messages/hu/Makefile
modules/http/tests/Makefile
modules/plug/Makefile
modules/pop3/Makefile
modules/pop3/messages/Makefile
modules/pop3/messages/en/Makefile
modules/pop3/messages/hu/Makefile
modules/smtp/Makefile
modules/smtp/tests/Makefile
modules/telnet/Makefile
modules/telnet/tests/Makefile
modules/whois/Makefile
munin_plugins/Makefile
nagios_plugins/Makefile
pylib/Makefile
pylib/Zorp/Config_.py
pylib/Zorp/Makefile
scripts/Makefile
tests/Makefile
tests/python/Makefile
tests/tools/Makefile
tests/unit/Makefile
tests/zorpctl/Makefile
zorp/Makefile
zorp/urlfilter/Makefile
zorpblgen/Makefile
zorpctl/Makefile],
[chmod +x debian/rules]
)
AC_OUTPUT
