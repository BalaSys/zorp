ZORP_H = \
	attach.h \
	authprovider.h \
	certchain.h \
	connection.h \
	coredump.h \
	dgram.h \
	dimhash.h \
	dispatch.h \
	ifmonitor.h \
	kzorp-kernel.h \
	kzorp.h \
	modules.h \
	nfdynexpect-kernel.h\
	plugsession.h \
	policy.h \
	proxy.h \
	proxycommon.h \
	proxygroup.h \
	proxyssl.h \
	proxysslhostiface.h \
	proxystack.h \
	pyattach.h \
	pycore.h \
	pydict.h \
	pydispatch.h \
	pyencryption.h \
	pyencryption_private.h \
	pyproxy.h \
	pyproxygroup.h \
	pysockaddr.h \
	pystream.h \
	pystruct.h \
	pyx509.h \
	pyx509chain.h \
	session.h \
	session_impl.h \
	sessionid.h \
	tpsocket.h \
	szig.h \
	urlfilter.h \
	x509lookup_crl_reloader.h \
	zorp.h \
	zorpconfig.h \
	zpython.h

if ENABLE_KZORP
ZORP_H += \
	kzorp.h kzorp-kernel.h
endif


ZORP_H += \
	urlfilter_blacklist.h

pkgincludedir=$(includedir)/zorp
pkginclude_HEADERS = $(ZORP_H)
