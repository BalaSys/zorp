SUBDIRS = . zorp

AM_CXXFLAGS = @LIBZORP_CXXFLAGS@

lib_LTLIBRARIES = libzorp.la

libzorp_la_LDFLAGS = \
	@LIBZORP_LIBS@ \
	-version-info $(LIBZORP_LT_COMPAT_PL) \
	-export-dynamic \
	-lstdc++fs

libzorp_la_SOURCES = \
	proxy.cc proxystack.cc modules.cc  \
	pycore.cc pysockaddr.cc pypolicy.cc \
	pyproxy.cc pystream.cc \
	zorp.cc \
	authprovider.cc \
	tpsocket.cc dimhash.cc \
	szig.cc \
	pydispatch.cc dispatch.cc \
	attach.cc connection.cc pyattach.cc \
	plugsession.cc  zpython.cc \
	dgram.cc \
	pydict.cc pystruct.cc \
	ifmonitor.cc proxygroup.cc pyproxygroup.cc \
	coredump.cc \
	proxyssl.cc pyx509.cc proxysslhostiface.cc \
	certchain.cc pyx509chain.cc \
	session.cc \
	pyencryption.cc x509lookup_crl_reloader.cc \
	urlfilter.cc

if ENABLE_KZORP
libzorp_la_SOURCES += kzorp.cc
endif


libzorp_la_SOURCES += \
	urlfilter_blacklist.cc
