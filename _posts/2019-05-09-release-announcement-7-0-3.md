---
layout:      post
title:       Release Notes 7.0.3
date:        2019-05-09 17:29:41
author:      Balasys Development Team
categories:
  - blog
  - release notes
---

Features
--------

* Zorp now can recognise the target (server) of any TLS encrypted connections
  analyzing the [server name indication](https://en.wikipedia.org/wiki/Server_Name_Indication)
  (SNI) part of TLS handshake message and different services can be started
  according to the fact whether a detected server name (`SNIDetector`) matches
  to a given expression (eg: `RegexMatcher`).

Deprecations
------------

* Completely removed `.*(Listener|Receiver)` classes. The change does not
  affect Zorp installations which are configured and managed by ZMS. The Zorp
  installations which are managed manually can use `.*Dispatcher` classes just
  like in 6.0.x versions.
