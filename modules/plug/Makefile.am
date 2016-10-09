pkgdatadir = @ZORP_PYTHON_DIR@
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
AM_CPPFLAGS = @MODULES_CPPFLAGS@

pkgdata_DATA = Plug.py

pkglib_LTLIBRARIES = libplug.la

libplug_la_SOURCES = plug.cc

EXTRA_DIST = $(pkgdata_DATA)
