SUBDIRS =
DIST_SUBDIRS =


SUBDIRS += . messages tests
DIST_SUBDIRS += . messages tests

pkgdatadir = @ZORP_PYTHON_DIR@
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
AM_CPPFLAGS = @MODULES_CPPFLAGS@
AM_CFLAGS = @CFLAGS@ -W

pkgdata_DATA = Http.py

pkglib_LTLIBRARIES = libhttp.la

libhttp_la_SOURCES = http.cc httpproto.cc httpfltr.cc httpfltr.h httpmisc.cc \
                     httphdr.cc httpftp.cc http.h httpcommon.h

EXTRA_DIST =  $(pkgdata_DATA)
