---
layout:      post
title:       Release Notes 6.0.11
date:        2017-12-07 17:12:28
author:      Balasys Development Team
categories:
  - blog
  - release notes
---

Improvements
------------

### Proxies

* The Zorp HTTP proxy can now bridge [Basic access authentication](https://en.wikipedia.org/wiki/Basic_access_authentication)
and [Form-based authentication](https://en.wikipedia.org/wiki/Form-based_authentication),
allowing you to transform form-based authentication
on the client side into basic access authentication on the server side.

Fixes
-----

### Critical

* Fixed the handling of [SMTP optional extensions](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol#Optional_extensions)
when the [`tls_passthrough`](https://www.balabit.com/documents/zorp-6.0-guides/en/zorp-gateway-guide-reference/html-single/index.html#python.Smtp.AbstractSmtpProxy_tls_passthrough)
attribute is enabled in the SMTP proxy. Earlier Zorp removed the
`STARTTLS` extensions from the extension list if the `tls_passthrough`
attribute was enabled, so the client could never initiate TLS connection.
* In some cases, expired self-side certificates were treated as valid.
This has been corrected.

### Important

* Fixed the free mechanism of Python object when `DetectorService` is used,
which caused a crash while detecting the type of the network traffic.
* Fixed access of Google services (search, calendar, ...) with Google
Chrome/chromium when TLS is terminated on the firewall [`TwoSidedEncryption`](https://www.balabit.com/documents/zorp-6.0-guides/en/zorp-gateway-guide-reference/html-single/index.html#python.Encryption.TwoSidedEncryption). Now the mentioned services can be accessed without any problem.

### Moderate

* The `zorpctl szig` command, always returned `-1` as thread ID. This has been
corrected.

### Low

* Form-based authentication redirected the client to an invalid URL
containing only `https` instead of the real URL to be redirected to. This has
been corrected.
