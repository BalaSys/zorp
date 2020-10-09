AM_CXXFLAGS=@ZORP_CXXFLAGS@
AM_LDFLAGS=@ZORP_LIBS@

SUBDIRS = urlfilter

sysconfdir = ${ZORP_SYSCONFDIR}
sbin_PROGRAMS = zorp

zorp_SOURCES = main.cc

sysconf_DATA = policy.py.http.sample policy.py.https.sample policy.py.ssh.sample dh.pem

EXTRA_DIST = $(sysconf_DATA) logtags.txt logtags_gperf.c logtags_gperf.h logtags.gperf

install-exec-local:
	$(MKDIR_P) $(DESTDIR)/${ZORP_SYSCONFDIR}
	$(MKDIR_P) $(DESTDIR)/${ZORP_SYSCONFDIR}/urlfilter
	chmod 0700 $(DESTDIR)/${ZORP_SYSCONFDIR}
	$(MKDIR_P) $(DESTDIR)/${ZORP_PIDFILEDIR}
	$(MKDIR_P) $(DESTDIR)/${ZORP_STATEDIR}/quarantine
	$(MKDIR_P) $(DESTDIR)/${ZORP_STATEDIR}/tmp
	$(MKDIR_P) $(DESTDIR)/${ZORP_STATEDIR}/audit
	$(MKDIR_P) $(DESTDIR)/${ZORP_STATEDIR}/urlfilter
	$(MKDIR_P) $(DESTDIR)/${ZORP_STATEDIR}/cores

main.c: logtags_gperf.c

BUILT_SOURCES = logtags_gperf.c logtags_gperf.h logtags.gperf

logtags_gperf.c: logtags.gperf logtags_gperf.h
	$(GPERF) -e ',' -L C++ -Z LogTagHash -t -N  lookup $< > $@.T && mv $@.T $@

logtags_gperf.h: logtags.txt
	$(top_srcdir)/scripts/genlutable.sh header LOGTAG $< >$@.tmp && mv $@.tmp $@

logtags.gperf: logtags.txt
	$(top_srcdir)/scripts/genlutable.sh gperf LOGTAG $< >$@.tmp && mv $@.tmp $@
