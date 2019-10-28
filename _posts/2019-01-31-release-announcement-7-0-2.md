---
layout:      post
title:       Release Notes 7.0.2
date:        2019-01-31 16:13:12
author:      Balasys Development Team
categories:
  - blog
  - release notes
---

Fixes
-----

#### Critical

* Fixed handling the case when no A/AAAA/CNAME record relates to a domain
  name. It caused that kZorp daemon is crashed and not started again. It may
  happen if and only if there is at least one hostname-based zone where the
  domain meets the mentioned criteria.
* Fixed performance issue in DNS cache update. It caused high CPU usage by
  kZorp daemon. Configurations with large number (>100) of hostname-based
  zones may be affected.
* Fixed handling the case when a hostname is resolved to a IPv4-mapped IPv6
  address. It caused that kZorp daemon is crashed and not started again. It
  may happen if and only if there is at least one hostname-based zone where
  the domain meets the mentioned criteria.
  
#### Low

* Made some generic performance improvement which affect the whole Zorp
  Gateway product. It cause minor speed-up (1-2%) among other things some
  proxies (eg: `HttpProxy`, `SmtpProxy`, ...).
