SUBDIRS = messages

pkgdatadir = @ZORP_PYTHON_DIR@
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
AM_CPPFLAGS = @MODULES_CPPFLAGS@

pkgdata_DATA = Pop3.py

pkglib_LTLIBRARIES = libpop3.la

libpop3_la_SOURCES = pop3.cc pop3misc.cc pop3cmd.cc pop3policy.cc pop3data.cc pop3auth.cc  pop3cmd.h pop3.h pop3policy.h pop3misc.h pop3data.h

EXTRA_DIST = $(pkgdata_DATA)
