pkgdatadir = @ZORP_PYTHON_DIR@
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
AM_CPPFLAGS = @MODULES_CPPFLAGS@

pkgdata_DATA = Finger.py

pkglib_LTLIBRARIES = libfinger.la

libfinger_la_SOURCES = finger.cc

EXTRA_DIST = $(pkgdata_DATA)
