SUBDIRS = . messages tests
DIST_SUBDIRS = . messages tests

pkgdatadir = @ZORP_PYTHON_DIR@
pkglibdir = ${ZORP_LIBDIR}
AM_LDFLAGS = @MODULES_LIBS@
AM_CXXFLAGS = @MODULES_CXXFLAGS@

pkglib_LTLIBRARIES = libhttp.la

libhttp_la_SOURCES = http.cc httpproto.cc httpfltr.cc httpfltr.h httpmisc.cc \
                     httphdr.cc httpftp.cc http.h httpcommon.h \
                     http_url_filter.h http_url_filter.cc
