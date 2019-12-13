---
layout:      post
title:       Release Notes 7.0.4
date:        2019-10-24 16:13:12
author:      Balasys Development Team
categories:
  - blog
  - release notes
---

Improvements
------------

* Made the Zorp compatible with TLS 1.3. It does not mean that Zorp supports TLS
  1.3. Earlier Advanced Protocol Recognition (APR) SNI and server certificate
  detector components might have failed if the client initiated a TLS 1.3
  connection.  Now these detectors work well with any version of TLS 1.3
  protocols. In case of TLS offloading/interception TLS 1.3 is explicitly
  disabled, so it cannot work even if the underlaying library version
  (>= OpenSSL 1.1.1) makes it possible to use TLS 1.3 with Zorp. This will be
  the behavior until Zorp has explicit TLS 1.3 support to avoid any operational
  and interoperability problems.

Usability
---------

* Reloading a non-running Zorp instance now causes error. Earlier this error was
  silently suppressed.

Fixes
-----

#### Moderate

* Fixed kZorp service starting mechanism. Earlier when the service was started
  it could return before Zone related configurations were downloaded to
  kZorp. This might cause Zorp services fail to start as their configurations
  referred to Zones that were not downloaded yet. Now Zorp services wait for
  the Zone download to finish.

#### Low

* Duplicate CA/CRL directory related attributes were removed. Earlier there
  were `(ca|crl)(_verify)?_directory` attributes in `CertificateVerifier` class
  used in `EncryptionPolicy`. The usage of `(ca|crl)_directory)` attributes was
  heavily memory intensive and the CA/CRL files were loaded at the setup time of
  the `EncryptionPolicy` while `(ca|crl)_verify_directory` attributes are
  moderately CPU intensive and load the CA/CRL files on demand. Considering the
  latter version has much more advantages than disadvantages the former version
  was removed and is now automatically converted to the latter version.
* Use DH parameters defined in RFC 3526 instead of generating custom one.
  Earlier during the installation of Zorp a DH parameter was generated which
  might take a long time in lack of entrophy. Now the 4096-bit DH parameter is
  based on RFC 3526.
