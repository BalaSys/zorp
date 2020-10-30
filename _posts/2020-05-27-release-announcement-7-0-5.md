---
layout:      post
title:       Release Notes 7.0.5
date:        2020-05-27 14:00:00
author:      Balasys Development Team
categories:
  - blog
  - release notes
---

Features
--------

* Zorp now supports the latest version (1.3) of Transport Layer Security (TLS)
  protocol both on client and server side of Zorp. TLS 1.3 support is disabled
  in `EncryptionPolicy` classes by default so it should be explicitely enabled
  in existing configurations.


Fixes
-----

#### Critical

* Fixed an SNAT issue in Zorp kernel module kZorp, caused that a traffic which
  source address was translated (SNAT) by Service was translated again if there
  was a rule which was matched to the traffic translated by the Service and its
  service is a PFService where *use client address as source* parameter is set.
* Fixed a permission handling problem in Zorp Munin plugins which caused
  the RSS/VSZ memory usage of Zorp instances not being displayed.
* Fixed a significant memory leak in certificate chain building (10-100 MB
  per day), both in TLS offloading and interception scenarios.

#### Moderate

* Fixed kZorp daemon and systemd integration. Earlier kZorp might not responde
  to systemd if there were no hostname based *Zones* in the configuration. It
  resulted in the kZorp daemon being terminated by systemd.
