pkgdatadir = @ZORP_PYTHON_DIR@
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
AM_CPPFLAGS = @MODULES_CPPFLAGS@

pkgdata_DATA = Whois.py

pkglib_LTLIBRARIES = libwhois.la

libwhois_la_SOURCES = whois.cc

EXTRA_DIST = $(pkgdata_DATA)
