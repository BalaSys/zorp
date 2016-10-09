SUBDIRS = . tests

pkgdatadir = @ZORP_PYTHON_DIR@
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
AM_CPPFLAGS = @MODULES_CPPFLAGS@

pkgdata_DATA = Smtp.py

pkglib_LTLIBRARIES = libsmtp.la

libsmtp_la_SOURCES = smtp.cc smtpcmd.cc smtpdata.cc smtpmsg.cc smtppolicy.cc smtp.h smtpmsg.h

EXTRA_DIST = $(pkgdata_DATA) 

