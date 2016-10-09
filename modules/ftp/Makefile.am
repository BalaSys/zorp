SUBDIRS = tests

pkgdatadir = @ZORP_PYTHON_DIR@
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
AM_CPPFLAGS = @MODULES_CPPFLAGS@

pkgdata_DATA = Ftp.py

pkglib_LTLIBRARIES = libftp.la

libftp_la_SOURCES = ftp.cc ftphash.cc ftpmsg.cc ftpcmd.cc ftpolicy.cc ftpdata.cc ftp.h ftpcmd.h ftphash.h ftpolicy.h ftpmsg.h

EXTRA_DIST = $(pkgdata_DATA) 
