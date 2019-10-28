---
layout:      post
title:       Release Notes 7.0.1
date:        2018-09-06 13:06:07
author:      Balasys Development Team
categories:
  - blog
  - release notes
---

Improvements
------------

* Ubuntu 18.04 support
* Systemd support
* Automatic debug symbol packages (Debian/Ubuntu)
* Rewritten `zorpctl` functionality (in Python)

Usability
---------

* Improved help message readability in case of `kzorp-client` command line
  tool's evaluate functionality.
* The source port parameter is now optional in case of `kzorp-client` command
  line tool's evaluate functionality.

Fixes
-----

#### Critical

* Fixed session id handling. The problem caused that session id is not
  increased when a new connection is arrived. The only affected service type
  is `DetectorService`, any other service types work well.

#### Moderate

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

#### Low

* Give deprecation warning when Zorp starts if either `ca_directory` or
  `crl_directory` parameters are set in any `ClientCertificateVerifier` which
  is used in any `EncryptionPolicy` as these parameters will be removed in
  next LTS version.
* Fixed parameter handling in case of `kzorp-client` command line tool's
  evaluate functionality. The problem caused crashed when non-existing
  interface was given as source interface parameter.
* Fixed handling of UTF-8 characters in case of username and password entries
  of form-based authentication page.

Deprecations
------------

* Proxy-based SSL/TLS settings
    * `EncryptionPolicy` should be used in the following
* `Listener` and `Receiver` classes
    * `Dispatcher` classes should be used in the following
* CRL related options
    * `setup_[ca|crl]_list proxy ssl callback`
        * there is no alternative for this callback
    * `[ca|crl]_directory`
        * `verify_[ca|crl]_directory` should be used in the following
    * `[client_|server_]?[ca|crl]_directory`
        * `verify_[ca|crl]_directory` should be used in the following
        * it could be use in ZMS 6.x
    * `[client|server]_local_[ca|crl]_list`
        * `verify_[ca|crl]_directory` should be used in the following
    * `[client|server]_cagroup_directories`
        * `verify_[ca|crl]_directory` should be used in the following
* `OneToOneNat`, `OneToOneMultiNAT` and `StaticNAT` classes
    * `GeneralNAT` classes should be used in the following
