Name:			zorp
Version:		7.0.5
Release:		1%{?dist}
URL:			https://balasys.github.io/zorp/
%if 0%{?fedora}
%else
Vendor:			BalaSys IT
Packager:		BalaSys Development Team <devel@balasys.hu>
%endif

Source:			zorp_%{version}.tar.xz
Summary:		An advanced protocol analyzing firewall
License:		GPL-2.0
Group:			System/Daemons
BuildRequires:		binutils-devel
BuildRequires:		automake
BuildRequires:		autoconf
BuildRequires:		autoconf-archive
%if 0%{?fedora} || 0%{?rhel} || 0%{?centos}
BuildRequires:		docbook-style-xsl
%else
BuildRequires:		docbook-xsl-stylesheets
%endif
BuildRequires:		libtool
BuildRequires:		gcc-c++
BuildRequires:		libxslt
BuildRequires:		libzorpll-7_0-5-devel
BuildRequires:		boost-devel
BuildRequires:		python-devel
BuildRequires:		binutils-devel
BuildRequires:		glib2-devel
BuildRequires:		zlib-devel

Requires:		zorp-base
Requires:		python-zorp-base
Requires:		py-radix
Requires:		python-pydns
%if 0%{?fedora} || 0%{?rhel} || 0%{?centos}
Requires:		pyOpenSSL
Requires(pre):		shadow-utils
%else
Requires:		python-pyOpenSSL
Requires(pre):		pwdutils
Requires(pre):		shadow
%endif

%{!?__python2: %global __python2 /usr/bin/python2}
%global __python %{__python2}

%{!?python2_sitelib: %global python2_sitelib %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%{!?python2_sitearch: %global python2_sitearch %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}

BuildRoot:              %{_tmppath}/%{name}-%{version}-build

%description
Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions
are scriptable with the Python based configuration language.

Zorp has been successfully deployed in demanding environments like the
protection of high traffic web sites, or the protection of large intranets.
Since the protocol analysis is strict and many of the common exploits
violate the application protocol they are injected into, a large percentage
of the attacks do not cross a Zorp based firewall even if the given service
is permitted.

%package devel
Summary:                Headers for zorp
Group:                  System/Daemons
Requires:               libzorpll-7_0-5-devel

%description devel
This package provides header files for zorp

%prep
%setup -q -n zorp

%build
autoreconf -if
%configure --disable-werror
make %{?_smp_mflags}

%install
%make_install

%pre
getent group zorp >/dev/null || groupadd -r zorp
getent passwd zorp >/dev/null || useradd -r -g zorp -d /var/run/zorp -s /bin/bash -c "user for Zorp" zorp

%post
ldconfig

%postun
ldconfig

%files
%defattr(-,root,root)

%{_mandir}/man5/instances.conf.5.gz
%{_mandir}/man5/policy.py.5.gz
%{_mandir}/man8/*
%{_sbindir}/zorp
%{_sbindir}/zorpblgen
%{_sbindir}/zorpctl

%dir %{python2_sitelib}/Zorp
%dir %{python2_sitelib}/zorpctl
%{python2_sitelib}/Zorp/Auth.py
%{python2_sitelib}/Zorp/AuthDB.py
%{python2_sitelib}/Zorp/Cache.py
%{python2_sitelib}/Zorp/Chainer.py
%{python2_sitelib}/Zorp/Core.py
%{python2_sitelib}/Zorp/Detector.py
%{python2_sitelib}/Zorp/Dispatch.py
%{python2_sitelib}/Zorp/Encryption.py
%{python2_sitelib}/Zorp/Globals.py
%{python2_sitelib}/Zorp/Keybridge.py
%{python2_sitelib}/Zorp/FileLock.py
%{python2_sitelib}/Zorp/Matcher.py
%{python2_sitelib}/Zorp/NAT.py
%{python2_sitelib}/Zorp/Proxy.py
%{python2_sitelib}/Zorp/Router.py
%{python2_sitelib}/Zorp/Rule.py
%{python2_sitelib}/Zorp/Resolver.py
%{python2_sitelib}/Zorp/Service.py
%{python2_sitelib}/Zorp/Session.py
%{python2_sitelib}/Zorp/SockAddr.py
%{python2_sitelib}/Zorp/Stack.py
%{python2_sitelib}/Zorp/Stream.py
%{python2_sitelib}/Zorp/Util.py
%{python2_sitelib}/Zorp/Zorp.py

%{python2_sitelib}/zorpctl/CommandResults.py
%{python2_sitelib}/zorpctl/Instances.py
%{python2_sitelib}/zorpctl/PluginAlgorithms.py
%{python2_sitelib}/zorpctl/ProcessAlgorithms.py
%{python2_sitelib}/zorpctl/SZIGMessages.py
%{python2_sitelib}/zorpctl/szig.py
%{python2_sitelib}/zorpctl/UInterface.py
%{python2_sitelib}/zorpctl/utils.py

%if 0%{?fedora} || 0%{?rhel} || 0%{?centos}
%{python2_sitelib}/Zorp/*.pyc
%{python2_sitelib}/zorpctl/*.pyc
%{python2_sitelib}/Zorp/*.pyo
%{python2_sitelib}/zorpctl/*.pyo
%endif

%dir %attr(750,root,zorp) %{_sysconfdir}/zorp
%config %attr(640,root,zorp) %{_sysconfdir}/zorp/*.sample
%config %attr(644,root,zorp) %{_sysconfdir}/zorp/dh.pem
%dir %attr(755,root,zorp) %{_sysconfdir}/zorp
%config %attr(644,root,zorp) %{_sysconfdir}/zorp/urlfilter
%config %attr(644,root,zorp) %{_sysconfdir}/zorp/urlfilter/whitelist
%config %attr(644,root,zorp) %{_sysconfdir}/zorp/urlfilter/whitelist/domains
%config %attr(644,root,zorp) %{_sysconfdir}/zorp/urlfilter/whitelist/urls

%package -n libzorp-7_0-5
Summary:                The runtime library of Zorp
Group:                  System/Daemons

%description -n libzorp-7_0-5
Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions

The library needed to run zorp.

%files -n libzorp-7_0-5
%defattr(-,root,root)

%dir %{_libdir}/zorp

%{_libdir}/libzorp*.so.*
%{_libdir}/libzorpproxy*.so.*

%post -n libzorp-7_0-5
ldconfig

%postun -n libzorp-7_0-5
ldconfig

%package -n libzorp-7_0-devel
Summary:                Development files needed to compile Zorp modules
Group:                  System/Daemons

%description -n libzorp-7_0-devel
Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions
are scriptable with the Python based configuration language.

These are the files you need to compile a zorp module.

%files -n libzorp-7_0-devel
%defattr(-,root,root)

%dir %{_libdir}/zorp

%{_includedir}/zorp
%{_libdir}/libzorp.la
%{_libdir}/libzorp.so
%{_libdir}/libzorpproxy.la
%{_libdir}/libzorpproxy.so
%{_libdir}/pkgconfig/libzorp.pc
%{_libdir}/pkgconfig/libzorpproxy.pc
%{_datadir}/zorp/moduledist.conf

%package base
Summary:                Base files for zorp
Group:                  System/Daemons

%description base
Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions

Common files for Zorp and kZorp.

%files base
%attr(755,root,root) %{_mandir}/man5/zorpctl.conf.5.gz
%config(noreplace) %attr(640,root,zorp) %{_sysconfdir}/zorp/zorpctl.conf

%package -n python-zorp-base
Summary:                Base files for zorp
Group:                  System/Daemons

%description -n python-zorp-base
Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions

Common python files for Zorp and kZorp.

%files -n python-zorp-base
%{python2_sitelib}/Zorp/Base.py
%{python2_sitelib}/Zorp/Common.py
%{python2_sitelib}/Zorp/Config.py
%{python2_sitelib}/Zorp/Exceptions.py
%{python2_sitelib}/Zorp/Instance.py
%{python2_sitelib}/Zorp/InstancesConf.py
%{python2_sitelib}/Zorp/ResolverCache.py
%{python2_sitelib}/Zorp/Subnet.py
%{python2_sitelib}/Zorp/Zone.py
%{python2_sitelib}/Zorp/__init__.py
%{python2_sitelib}/zorpctl/__init__.py
%{python2_sitelib}/zorpctl/ZorpctlConf.py

%package modules
Summary:                Zorp proxy modules
Group:                  System/Daemons

%description modules

Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions
are scriptable with the Python based configuration language.

This package includes proxies for the protocols: FINGER, FTP, HTTP,
SSL, TELNET, WHOIS, and two general modules ANYPY and PLUG.

%files modules
%defattr(-,root,root)

%dir %{_libdir}/zorp

%{_libdir}/zorp/lib*.so*
%{_libdir}/zorp/lib*.la

%dir %{_datadir}/zorp

%dir %{_datadir}/zorp/http
%dir %{_datadir}/zorp/http/de
%dir %{_datadir}/zorp/http/en
%dir %{_datadir}/zorp/http/hu
%attr(644,root,root) %{_datadir}/zorp/http/en/*.html
%attr(644,root,root) %{_datadir}/zorp/http/de/*.html
%attr(644,root,root) %{_datadir}/zorp/http/hu/*.html

%dir %{_datadir}/zorp/pop3
%dir %{_datadir}/zorp/pop3/en
%dir %{_datadir}/zorp/pop3/hu
%attr(644,root,root) %{_datadir}/zorp/pop3/en/reject.msg
%attr(644,root,root) %{_datadir}/zorp/pop3/hu/reject.msg

%{python2_sitelib}/Zorp/AnyPy.py
%{python2_sitelib}/Zorp/APR.py
%{python2_sitelib}/Zorp/Finger.py
%{python2_sitelib}/Zorp/Ftp.py
%{python2_sitelib}/Zorp/Http.py
%{python2_sitelib}/Zorp/Plug.py
%{python2_sitelib}/Zorp/Pop3.py
%{python2_sitelib}/Zorp/Smtp.py
%{python2_sitelib}/Zorp/Telnet.py
%{python2_sitelib}/Zorp/Whois.py


%package munin-plugins
Summary:                Munin monitoring plugins for Zorp
Group:                  System/Daemons
Requires:               munin-node


%description munin-plugins

Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions
are scriptable with the Python based configuration language.

This package contains plugins for the Munin monitoring tool.

%files munin-plugins
%dir %{_datadir}/munin/
%dir %{_datadir}/munin/plugins/
%{_datadir}/munin/plugins/*
%dir %{_sysconfdir}/munin
%dir %{_sysconfdir}/munin/plugin-conf.d
%config %attr(644,root,root) %{_sysconfdir}/munin/plugin-conf.d/*


%package nagios-plugins
Summary:                Nagios monitoring plugins for Zorp
Group:                  System/Daemons
Requires:               nrpe

%description nagios-plugins

Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions
are scriptable with the Python based configuration language.

This package contains plugins for the Nagios monitoring tool.

%files nagios-plugins
%dir %{_sysconfdir}/sudoers.d
%config %attr(440,root,root) %{_sysconfdir}/sudoers.d/zorp_nagios_plugins
%dir %{_sysconfdir}/nagios
%dir %{_sysconfdir}/nagios/nrpe.d
%config %attr(644,root,root) %{_sysconfdir}/nagios/nrpe.d/zorp.cfg
%dir %{_exec_prefix}/lib/nagios
%dir %{_exec_prefix}/lib/nagios/plugins
%{_exec_prefix}/lib/nagios/plugins/*

%package -n kzorp
Summary:                Python bindings for kzorp.
Group:                  System/Daemons

%description -n kzorp
Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions

Standalone daemon that handles zones and updates dynamic zones.


%changelog
* Wed May 27 2020 Balasys Development Team <devel@balasys.hu> - 7.0.5-1
  - New upstream release 7.0.5
* Thu Sep 12 2019 Balasys Development Team <devel@balasys.hu> - 7.0.4-1
  - New upstream release 7.0.4
* Tue Apr 23 2019 Balasys Development Team <devel@balasys.hu> - 7.0.3-1
  - New upstream release 7.0.3
* Thu Jan 31 2019 Balasys Development Team <devel@balasys.hu> - 7.0.2-1
  - New upstream release 7.0.2
* Wed Dec 5 2018 Balasys Development Team <devel@balasys.hu> - 7.0.1-1
  - New upstream release 7.0.1
* Wed Nov 21 2018 Balasys Development Team <devel@balasys.hu> - 7.0.1-0.2
  - New upstream release 7.0.1~alpha2
* Thu May 17 2018 Balasys Development Team <devel@balasys.hu> - 7.0.1-0.1
  - New upstream release 7.0.1~alpha1
* Thu May 10 2018 Balasys Development Team <devel@balasys.hu> - 6.0.12
  - New upstream release 6.0.12
* Wed Sep 13 2017 Balasys Development Team <devel@balasys.hu> - 6.0.11
  - New upstream release 6.0.11
* Fri Nov 25 2016 Balasys Development Team <devel@balasys.hu> - 6.0.10
  - New upstream release 6.0.10
* Wed Apr 13 2016 Balasys Development Team <devel@balasys.hu> - 6.0.9
  - New upstream release 6.0.9
* Sun Feb 21 2016 Balasys Development Team <devel@balasys.hu> - 6.0.8
  - New upstream release 6.0.8
* Sun Feb 21 2016 Balasys Development Team <devel@balasys.hu> - 6.0.8
  - New upstream release 6.0.8
* Wed Mar 4 2015 BalaBit Development Team <devel@balabit.hu> - 5.0.0
- Fixed several packaging warings and errors
