ACLOCAL_AMFLAGS = -I m4

SUBDIRS = lib libproxy modules zorp pylib doc debian zorpctl scripts tests munin_plugins nagios_plugins zorpblgen
DIST_SUBDIRS = $(SUBDIRS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libzorp.pc libzorpproxy.pc


pkgdatadir=${ZORP_DATADIR}
pkgdata_DATA = moduledist.conf

EXTRA_DIST = dist.conf BUGS WHATIS.TXT VERSION ${pkgconfig_DATA} ${pkgdata_DATA}

COPYING: COPYING.in@PACKAGE_SUFFIX@
	cp $< $@

MAINTAINERCLEANFILES=dist.conf COPYING

dist.conf: dist.conf.in
	$(top_builddir)/config.status --file $@:$<
