
EXTRA_DIST = urls domains

install-exec-local:
	$(INSTALL) -m 755 -d $(DESTDIR)/${ZORP_SYSCONFDIR}/urlfilter/whitelist
	$(INSTALL_DATA) -t $(DESTDIR)/${ZORP_SYSCONFDIR}/urlfilter/whitelist $(srcdir)/urls $(srcdir)/domains

