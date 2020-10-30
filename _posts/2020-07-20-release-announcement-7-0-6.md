---
layout:      post
title:       Release Notes 7.0.6
date:        2020-07-20 16:10:33
author:      Balasys Development Team
categories:
  - blog
  - release notes
---

Fixes
-----

#### Low

* Fixed a memory leak that appeared only on a *Service* and/or a *Proxy* handling
  TLS connections (encryption policy is used). The scale of memory leak
  was about some megabytes per hundred thousand connections.
