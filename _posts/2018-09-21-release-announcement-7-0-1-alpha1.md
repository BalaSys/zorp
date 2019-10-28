---
layout:      post
title:       Release Notes 7.0.1-alpha1
date:        2018-09-11 09:53:26
author:      Balasys Development Team
categories:
  - blog
  - release notes
---

Fixes
-----

### Moderate

* Fixed a memory leak which occurred when Zorp failed to read on the
  client-side socket during a TLS connection.
* Fixed reply code sent by `SMTPProxy` when a received mail is rejected.
  Earlier when the proxy wanted to reject an incoming mail (e.g. it contains
  a virus) it replied with an error code indicating only temporary rejection
  (`421`) and the server tried to send the mail to the Zorp several times. Now
  the error code (`550`) is sent indicating permanent rejection, so a valid
  server does not try to resend the mailto Zorp.
* Fixed Zorp thread count drawing Munin plugin. Due to the problem the
  plugin did not serve data to the Munin node and the graph was not created at
  all.
* Fixed verbosity level of logs generated when Zorp cannot read on a UDP
  connection. The verbosity level of relevant messages is unchanged, only the
  verbosity level of messages about temporary failures (`EAGAIN`) is
  increased.
* Fixed information leak when form-based authentication is used in HTTP proxy,
  now Zorp does not forward anywhere `ZorpRealm` cookie, which identify the
  session of logged in user, to the remote peer (server).
* Fixed authentication cache handling in HTTP proxy when client uses basic
  authentication. Now Zorp does not send `ZorpRealm` cookies, which identify
  the session (potentially sensitive information) to the proxy.

### Low

* Give deprecation warning when Zorp starts if either `ca_directory` or
  `crl_directory` parameters are set in any `ClientCertificateVerifier` which
  is used in any `EncryptionPolicy` as these parameters will be removed in
  next LTS version.
