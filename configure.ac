dnl Process this file with autoconf to produce a configure script.
dnl

AC_CONFIG_MACRO_DIR([m4])
m4_include(m4/ax_cxx_compile_stdcxx_11.m4)

AC_INIT([zorp], m4_esyscmd([tr -d '\n' < VERSION]))
AC_CONFIG_SRCDIR(zorp/main.cc)
AM_INIT_AUTOMAKE([no-define foreign])

dnl ***************************************************************************
dnl Definitions

BROCHURE_VERSION="6"
ZORP_PRODUCT_NAME="Zorp GPL"

dnl ***************************************************************************
dnl Dependencies

GLIB_MIN_VERSION="2.32.0"
ZORPLL_MIN_VERSION="6.0.8.0"
ZORPLIC_MIN_VERSION="6.0.3.0"
ZORPMISC_MIN_VERSION="6.0.3.0"
OPENSSL_MIN_VERSION="1.0.1"
PYTHON_MIN_VERSION="2.7"
PYTHON_MAX_VERSION="2.8"

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

AM_CONFIG_HEADER(lib/zorp/zorpconfig.h)
AC_PREFIX_DEFAULT(/usr/local)

if test "x$prefix" = "xNONE"; then
	prefix=$ac_default_prefix
fi

zorp_srcdir=$top_srcdir

AC_ARG_ENABLE(debug,
              [  --enable-debug       Enable debug information & messages (default: no)],,
	      enable_debug=no)

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

AC_ARG_WITH(pidfiledir,
              [  --with-pidfiledir=[path]   Path to run directory where pidfile is stored],
              pidfiledir="$with_pidfiledir",
              pidfiledir='${localstatedir}/run/zorp/')

ZORP_MUNIN_CONF_DIR="${sysconfdir}/munin/plugin-conf.d"
ZORP_NAGIOS_CONF_DIR="${sysconfdir}/nagios/nrpe.d"
ZORP_SUDOERSD_CONF_DIR="${sysconfdir}/sudoers.d"
sysconfdir="${sysconfdir}/zorp"
#datadir='${prefix}/share/zorp'
libdir='${prefix}/lib'

dnl ***************************************************************************
dnl Argument processing which might affect detection

if test "x$enable_debug" = "xyes"; then
  # maybe we should check whether /usr/lib/debug exists
  LIBS="$LIBS -L/usr/lib/debug"
  CXXFLAGS="$CXXFLAGS -O0"
else
  CXXFLAGS="$CXXFLAGS -O2 "
fi

dnl ***************************************************************************
dnl Checks for programs.

AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_CXX
AX_CXX_COMPILE_STDCXX_11(noext)
AC_PROG_CPP
AC_PROG_CXXCPP
AC_DISABLE_STATIC

AC_LANG_PUSH([C++])

AC_COMPILE_IFELSE([AC_LANG_SOURCE(
  [[template <typename T>
    struct check {
      static_assert(sizeof(int) <= sizeof(T), "not big enough");
    };

    typedef check<check<bool>> right_angle_brackets;

    int a;
    decltype(a) b;

    typedef check<int> check_type;
    check_type c;
    check_type&& cr = static_cast<check_type&&>(c);]])],,
  AC_MSG_FAILURE(['$CXX $CXXFLAGS' does not accept full ISO C++11]))

AM_PROG_LIBTOOL

dnl ***************************************************************************
dnl Checks for header files.


AC_CHECK_HEADERS(sys/capability.h sys/prctl.h sys/syscall.h limits.h stdbool.h stdint.h)

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

save_LIBS=$LIBS
LIBS="$LIBS $SOCK_LIBS"
AC_CHECK_FUNCS(socket)
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

LIBS=$save_LIBS

PKG_CHECK_MODULES(GLIB, glib-2.0 >= $GLIB_MIN_VERSION,,
	AC_MSG_ERROR(Cannot find GLib library version >= $GLIB_MIN_VERSION: is pkg-config in path?))

PKG_CHECK_MODULES(GMODULE, gmodule-2.0 >= $GLIB_MIN_VERSION,,
	AC_MSG_ERROR(Cannot find GModule library version >= $GLIB_MIN_VERSION: is pkg-config in path?))

PKG_CHECK_MODULES(GTHREAD, gthread-2.0 >= $GLIB_MIN_VERSION,,
	AC_MSG_ERROR(Cannot find GThread library version >= $GLIB_MIN_VERSION: is pkg-config in path?))

PKG_CHECK_MODULES(ZORPLL, zorplibll >= $ZORPLL_MIN_VERSION,,
	AC_MSG_ERROR(Cannot find ZORP Lowlevel library version >= $ZORPLL_MIN_VERSION: is pkg-config in path?))

PKG_CHECK_MODULES(OPENSSL, openssl >= $OPENSSL_MIN_VERSION,,
        AC_MSG_ERROR(Cannot find OpenSSL library version >= $OPENSSL_MIN_VERSION: is pkg-config in path?))

PKG_CHECK_MODULES(LIBPYTHON, python-2.7 >= $PYTHON_MIN_VERSION,,
	AC_MSG_ERROR(Cannot find Python library version >= $PYTHON_MIN_VERSION: is pkg-config in path?))
PKG_CHECK_MODULES(LIBPYTHON, python-2.7 < $PYTHON_MAX_VERSION,,
	AC_MSG_ERROR(Cannot find Python library version >= $PYTHON_MAX_VERSION: is pkg-config in path?))





if test "x$ac_cv_func_gethostbyname_r" = "xyes"; then
dnl	if test "`uname -s`" = "Linux"; then
dnl		AC_DEFINE(HAVE_LEAK_IN_GETHOSTBYNAME_R, 1, [We have a leak in gethostbyname_r, avoid using it])
	if test "`uname -s`" = "SunOS"; then
		AC_DEFINE(HAVE_SUN_GETHOSTBYNAME_R, 1, [We have a Solaris style gethostbyname_r];)
	fi
fi

save_LIBS="$LIBS"
LIBS="$LIBS $OPENSSL_LIBS"
AC_SEARCH_LIBS(DES_ecb_encrypt, eay32 crypto,
    AC_SEARCH_LIBS(des_ecb_encrypt, eay32 crypto))
AC_SEARCH_LIBS(SSL_accept, ssl32 ssl)
AC_CHECK_FUNC(ENGINE_by_id)
LIBS=$save_LIBS

if test "x$ac_cv_search_SSL_accept" = "xno"; then
        AC_ERROR(OpenSSL libraries required)
fi

dnl ***************************************************************************
dnl Misc checks

AC_SYS_LARGEFILE

ZORP_PROC="`uname -m`"
ZORP_OS="`uname -s`"
ZORP_OS_RELEASE="`uname -r | cut -d '.' -f 1-2`"

if test "x$ZORP_OS" = "xLinux";then
        CURRDATE=`date -R`
else
        CURRDATE=`date +"%a, %d %b %Y %H:%M:%S %Z"`
fi

dnl ***************************************************************************
dnl Export detected settings to Makefiles and Zorp

AC_SUBST(zorp_srcdir)
AC_SUBST(ZORP_PROC)
AC_SUBST(ZORP_OS)
AC_SUBST(ZORP_MUNIN_CONF_DIR)
AC_SUBST(ZORP_NAGIOS_CONF_DIR)
AC_SUBST(ZORP_PYTHON_DIR)
AC_SUBST(ZORPCTL_PYTHON_DIR)
AC_SUBST(ZORP_SUDOERSD_CONF_DIR)

zorpeval()
{
	OLD=$1
	NEW=`eval echo $1`
	while /usr/bin/test "x$OLD" != "x$NEW"
	do
		OLD=$NEW
		NEW=`eval echo $OLD`
	done
	echo $OLD
}

ZORP_MUNIN_DIR="${prefix}/share/munin/plugins"
ZORP_NAGIOS_DIR="${prefix}/lib/nagios/plugins"
ZORP_PYTHON_DIR="${pythondir}/Zorp"
ZORPCTL_PYTHON_DIR="${pythondir}/zorpctl"

zorp_sysconfdir="`zorpeval $sysconfdir`"
AC_DEFINE_UNQUOTED(ZORP_SYSCONFDIR, "$zorp_sysconfdir", [sysconfdir])
AC_DEFINE_UNQUOTED(ZORP_DATADIR, "`zorpeval $datadir/zorp`", [datadir])
zorp_libdir="`zorpeval $libdir/zorp`"
AC_DEFINE_UNQUOTED(ZORP_LIBDIR, "$zorp_libdir", [libdir])
AC_DEFINE_UNQUOTED(ZORP_STATEDIR, "`zorpeval $localstatedir`", [localstatedir])
zorp_pidfiledir="`zorpeval $pidfiledir`"
AC_DEFINE_UNQUOTED(ZORP_PIDFILEDIR, "$zorp_pidfiledir", [pidfiledir])

AC_SUBST(zorp_libdir)
AC_SUBST(zorp_sysconfdir)
AC_SUBST(zorp_pidfiledir)

CXXFLAGS="$CXXFLAGS -Wall -W -Werror-implicit-function-declaration -g -D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64"

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

dnl Library versioning, the resulting shared object is named:
dnl 	zorplib-<RELEASE>.so.<AGE>
dnl
VERSION_NOSNAPSHOT="`echo $VERSION | cut -d '+' -f 1`"

VERSION_MAJOR=`echo $VERSION_NOSNAPSHOT |  cut -d '.' -f 1`
VERSION_MINOR=`echo $VERSION_NOSNAPSHOT |  cut -d '.' -f 2`
VERSION_COMPAT=`echo $VERSION_NOSNAPSHOT |  cut -d '.' -f 3`

LIBZORP_LT_RELEASE="$VERSION_MAJOR.$VERSION_MINOR"
LIBZORP_LT_COMPAT_BRANCH="$VERSION_MAJOR.$VERSION_MINOR-$VERSION_COMPAT"
LIBZORP_LT_COMPAT_PL="$VERSION_COMPAT"

dnl ***************************************************************************
dnl Size check of pointers
AC_CHECK_SIZEOF(void *)

AC_SUBST(BROCHURE_VERSION)
AC_SUBST(SNAPSHOT_VERSION)
AC_SUBST(SOURCE_REVISION)

AC_DEFINE_UNQUOTED(ZORP_PRODUCT_NAME, "$ZORP_PRODUCT_NAME", [Required product name in license])
AC_SUBST(ZORP_PRODUCT_NAME)

AC_DEFINE_UNQUOTED(BROCHURE_VERSION, "$BROCHURE_VERSION", [Zorp brochure version])
AC_DEFINE_UNQUOTED(VERSION, "$PACKAGE_VERSION", [Zorp package version])
AC_DEFINE_UNQUOTED(ZORP_SOURCE_REVISION, "$SOURCE_REVISION", [Zorp source revision number])

AC_DEFINE_UNQUOTED(ENABLE_DEBUG, `enable_value $enable_debug`, [Enable debugging])
AC_DEFINE_UNQUOTED(ENABLE_TRACE, `enable_value $enable_trace`, [Enable trace messages])
AC_DEFINE_UNQUOTED(ENABLE_IPOPTIONS, `enable_value $enable_ip_options`, [Enable IP option processing])
AC_DEFINE_UNQUOTED(ENABLE_IPV6, `enable_value $enable_ipv6`, [Enable IPv6 support])
AC_DEFINE_UNQUOTED(ENABLE_PREFORK, `enable_value $enable_prefork`, [Enable prefork support])

# CPPFLAGS as supplied by dependencies
DEPS_CPPFLAGS="$CPPFLAGS $ZORPLL_CFLAGS $ZORPLIC_CFLAGS $ZORPMISC_CFLAGS $LIBPYTHON_CFLAGS $OPENSSL_CFLAGS $LIBADPALERTING_CFLAGS"
# CPPFLAGS defined to access local header files in addition to dependencies
CPPFLAGS="-I$top_srcdir/lib -I$top_srcdir $DEPS_CPPFLAGS"
# common libraries (dependencies)
LIBPROXY_CPPFLAGS="-I$top_srcdir/libproxy/ $CPPFLAGS"
MODULES_CPPFLAGS="-I$top_srcdir/libproxy/ $CPPFLAGS"

# Dependencies outside the source tree
DEPS_LIBS="$SOCK_LIBS $ZORPLL_LIBS $ZORPLIC_LIBS $ZORPMISC_LIBS $LIBPYTHON_LIBS $LIBPYTHON_DEPS $COREDUMP_LIBS $OPENSSL_LIBS"
# zorp library libs
LIBZORP_LIBS="$DEPS_LIBS $GLIB_LIBS $GMODULE_LIBS $GTHREAD_LIBS $LIBPYTHON_LIBS $OPENSSL_LIBS $PCAP_LIBS"
# Zorp main program
ZORP_LIBS="-L\$(top_builddir)/lib/ -lzorp $ZORPLL_LIBS $ZORPMISC_LIBS $ZORPLIC_LIBS $OPENSSL_LIBS $LIBADPALERTING_LIBS"
# libraries to link the zorp modules against (implicitly linked
# against the main binary, those does not need to be listed here
MODULES_LIBS="-L\$(top_builddir)/lib/ -lzorp -L\$(top_builddir)/libproxy/ -lzorpproxy $ZORPLL_LIBS $LIBPYTHON_LIBS"
# module test program libs
MODULETESTS_LIBS="$MODULES_LIBS $ZORP_LIBS $LIBPYTHON_LIBS"

dnl ***************************************************************************
dnl Coverage flags and libs
if test "x$enable_coverage" = "xyes"; then
        LDFLAGS="$LDFLAGS -fprofile-arcs -lgcov"
        CXXFLAGS="$CXXFLAGS -fprofile-arcs -ftest-coverage"
fi

if test "x$enable_predictable_random" = "xyes"; then
        AC_DEFINE(PREDICTABLE_RANDOM_ENABLED, 1, [Predictable random is enabled])
fi

AC_SUBST(DEPS_CPPFLAGS)
AC_SUBST(DEPS_LIBS)
AC_SUBST(ZLIB_LIBS)
AC_SUBST(GLIB_LIBS)
AC_SUBST(OPENSSL_LIBS)
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(UUID_LIBS)
AC_SUBST(UUID_CLAGS)
AC_SUBST(PCAP_LIBS)

AC_SUBST(LIBZORP_LIBS)


AC_SUBST(ZORP_LIBS)

AC_SUBST(LIBPROXY_CPPFLAGS)
AC_SUBST(MODULES_LIBS)
AC_SUBST(MODULES_CPPFLAGS)

AC_SUBST(MODULETESTS_LIBS)

dnl for zorpctl
AC_SUBST(SOCK_LIBS)

AC_SUBST(ZORP_MUNIN_DIR)
AC_SUBST(ZORP_NAGIOS_DIR)

AC_SUBST(ZORP_SYSCONFDIR)

date=`date +%Y/%m/%d`
AC_DEFINE_UNQUOTED(ZORP_CONFIG_DATE, "$date", [Configuration date])

cat <<EOF


Compile time options:
---------------------
debug: $enable_debug
coverage: $enable_coverage
ipoptions: $enable_ip_options
ipv6: $enable_ipv6
prefork: $enable_prefork


EOF

AC_SUBST(LIBZORP_LT_RELEASE)
AC_SUBST(LIBZORP_LT_COMPAT_BRANCH)
AC_SUBST(LIBZORP_LT_COMPAT_PL)

AC_SUBST(GLIB_MIN_VERSION)
AC_SUBST(ZORPLL_MIN_VERSION)
AC_SUBST(OPENSSL_MIN_VERSION)
AC_SUBST(PYTHON_MIN_VERSION)
AC_SUBST(CURRDATE)
AC_SUBST(pidfiledir)

AC_CONFIG_LINKS([pylib/Zorp/__init__.py:pylib/Zorp/__init__.py])

AC_CONFIG_FILES(
Makefile
debian/Makefile
doc/Makefile
doc/examples/Makefile
doc/man/Makefile
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
modules/http/tests/Makefile
modules/plug/Makefile
modules/pop3/Makefile
modules/pop3/messages/Makefile
modules/smtp/Makefile
modules/smtp/tests/Makefile
modules/telnet/Makefile
modules/telnet/tests/Makefile
modules/whois/Makefile
munin_plugins/Makefile
nagios_plugins/Makefile
pylib/Makefile
pylib/Zorp/Config.py
pylib/Zorp/Makefile
scripts/Makefile
tests/Makefile
tests/python/Makefile
tests/unit/Makefile
tests/zorpctl/Makefile
zorp/Makefile
zorpctl/Makefile
zorpctl_in_cc/Makefile
)
AC_OUTPUT
