#!/usr/bin/env python2.7
import unittest
from time import time

import Zorp.Common


class FakeDNSResolver(object):
    def __init__(self, hostname=None, ipv4_addrs=[], ipv6_addrs=[], ttl=300):
        self.hostname = hostname
        self.ipv4_addrs = ipv4_addrs
        self.ipv6_addrs = ipv6_addrs
        self.ttl = ttl
        self.default_ttl = 60
        self.errorstate = False

    def resolve(self, host):
        if self.errorstate:
            raise KeyError()
        return (self.ttl, self.ipv4_addrs, self.ipv6_addrs) if host == self.hostname else (self.default_ttl, [], [])


class TestResolverCache(unittest.TestCase):

    def test_resolvercache(self):
        from Zorp.ResolverCache import ResolverCache

        resolver = FakeDNSResolver('foundname', ['1.2.3.4','5.6.7.8'], ['fe80::59c7:f889:2f41:7e71',])
        cache = ResolverCache(resolver)

        cache.addHost('foundname')
        cache.addHost('notfoundname')

        self.assertEqual(cache.lookupCachedHostname('foundname'), (set(resolver.ipv4_addrs), set(resolver.ipv6_addrs)) )
        self.assertEqual(cache.lookupCachedHostname('notfoundname'), (set(), set()) )
        self.assertEqual(cache.lookupTTL('foundname'), resolver.ttl)
        self.assertEqual(cache.lookupTTL('notfoundname'), resolver.default_ttl)
        self.assertEqual(cache.lookupAddress(resolver.ipv4_addrs[0]), set((resolver.hostname,)) )
        self.assertEqual(cache.lookupAddress(resolver.ipv4_addrs[1]), set((resolver.hostname,)) )
        self.assertEqual(cache.lookupAddress(resolver.ipv6_addrs[0]), set((resolver.hostname,)) )

        self.assertRaises(KeyError, cache.lookupCachedHostname, 'unknownname')
        self.assertIsNone(cache.lookupTTL('unknownname'))
        self.assertIsNone(cache.lookupAddress('8.8.8.8'))

        self.assertFalse(cache.shouldUpdate())
        self.assertEqual(cache.getNextExpiration()[0], 'notfoundname')
        self.assertTrue(0 < cache.getNextExpiration()[1] <= time() + resolver.default_ttl)

        resolver.ipv4_addrs[1] = '8.8.8.8'
        resolver.ttl = 0
        self.assertFalse(cache.updateHostIfNeeded('foundname'))
        self.assertFalse(cache.updateHostIfNeeded('notfoundname'))
        cache.updateHost('notfoundname')
        self.assertNotIn('8.8.8.8', cache.lookupCachedHostname('foundname')[0])
        self.assertIsNone(cache.lookupAddress('8.8.8.8'))

        cache.updateHost('foundname')
        self.assertIn('8.8.8.8', cache.lookupCachedHostname('foundname')[0])
        self.assertIn('foundname', cache.lookupAddress('8.8.8.8'))
        self.assertTrue(cache.shouldUpdate())
        self.assertEqual(cache.getNextExpiration()[0], 'foundname')
        self.assertTrue(cache.getNextExpiration()[1] <= time())

        resolver.ipv4_addrs[0] = '4.3.2.1'
        self.assertEqual(cache.update(), ['foundname',])

        resolver.errorstate = True
        self.assertEqual(cache.update(), ['foundname',])
        self.assertEqual(cache.lookupCachedHostname('foundname'), (set(), set()) )
        self.assertNotIn('8.8.8.8', cache.lookupCachedHostname('foundname')[0])
        self.assertIsNone(cache.lookupAddress('8.8.8.8'))

        cache.removeHost('foundname')
        self.assertRaises(KeyError, cache.lookupCachedHostname, 'foundname')
        self.assertIsNone(cache.lookupTTL('foundname'))
        self.assertIsNone(cache.lookupAddress('8.8.8.8'))

        resolver.ttl = 120
        resolver.errorstate = False
        self.assertEqual(cache.lookupHostname('foundname'), (set(resolver.ipv4_addrs), set(resolver.ipv6_addrs)) )
        self.assertTrue(0 < cache.lookupTTL('foundname') <= time() + resolver.ttl)
        self.assertEqual(cache.lookupAddress(resolver.ipv4_addrs[0]), set((resolver.hostname,)) )
        self.assertEqual(cache.lookupAddress(resolver.ipv4_addrs[1]), set((resolver.hostname,)) )
        self.assertEqual(cache.lookupAddress(resolver.ipv6_addrs[0]), set((resolver.hostname,)) )


def null_log(*args):
    pass

if __name__ == '__main__':

    Zorp.Common.log = null_log

    unittest.main()
