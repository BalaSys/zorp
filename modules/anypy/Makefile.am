pkgdatadir = @ZORP_PYTHON_DIR@
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
AM_CPPFLAGS = @MODULES_CPPFLAGS@

pkgdata_DATA = AnyPy.py

pkglib_LTLIBRARIES = libanypy.la

libanypy_la_SOURCES = anypy.cc

EXTRA_DIST = $(pkgdata_DATA)
