############################################################################
##
## Copyright (c) 2000-2015 BalaBit IT Ltd, Budapest, Hungary
## Copyright (c) 2015-2018 BalaSys IT Ltd, Budapest, Hungary
##
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License along
## with this program; if not, write to the Free Software Foundation, Inc.,
## 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
##
############################################################################

"""
<module maturity="stable">
  <summary>
    The Encryption module defines encryption related policies.
  </summary>
  <description>
    <para>
        Starting with Zorp 6, the SSL/TLS framework of the Zorp proxies has been moved into a separate entity called Encryption policy. That way, you can easily share and reuse encryption settings between different services: you have to configure the Encryption policy once, and you can use it in multiple services. The SSL framework is described in <xref linkend="chapter_ssl"/>.
        (The earlier framework from the Proxy module is still available for compatibility reasons, but will be removed from the upcoming Zorp versions. For details on the parameters of this earlier framework, see <xref linkend="python.Proxy"/>.)
    </para>
    <note>
        <para>STARTTLS support is currently available only for the Ftp proxy to support FTPS sessions and for the SMTP proxy.</para>
    </note>
    <section xml:id="ssl-parameter-values">
        <title>SSL parameter constants</title>
        <inline type="enum" target="enum.ssl.verify"/>
        <inline type="enum" target="enum.ssl.ciphers"/>
        <inline type="enum" target="enum.ssl.ciphers_tlsv1_3"/>
        <inline type="enum" target="enum.ssl.shared_groups"/>
        <inline type="enum" target="enum.ssl.hso"/>
        <inline type="enum" target="enum.ssl.client_connection_security"/>
        <inline type="enum" target="enum.ssl.server_connection_security"/>
        <inline type="const" target="const.ssl.log"/>
        <inline type="const" target="const.ssl.hs"/>
    </section>
  </description>
  <metainfo>
    <enums>
      <enum maturity="stable" id="enum.ssl.verify">
        <description>
          Certificate verification settings
        </description>
        <item>
          <name>SSL_VERIFY_NONE</name>
          <description>Automatic certificate verification is disabled.</description>
        </item>
<!--        <item>
          <name>SSL_VERIFY_OPTIONAL</name>
          <description>Certificate is optional, all certificates are accepted.</description>
        </item>-->
        <item>
          <name>SSL_VERIFY_OPTIONAL_UNTRUSTED</name>
          <description>Certificate is optional, if present, both trusted and untrusted certificates are accepted.</description>
        </item>
        <item>
          <name>SSL_VERIFY_OPTIONAL_TRUSTED</name>
          <description>Certificate is optional, but if a certificate is present, only certificates signed by a trusted CA are accepted.</description>
        </item>
        <item>
          <name>SSL_VERIFY_REQUIRED_UNTRUSTED</name>
          <description>Valid certificate is required, both trusted and untrusted certificates are accepted.</description>
        </item>
        <item>
          <name>SSL_VERIFY_REQUIRED_TRUSTED</name>
          <description>Certificate is required, only valid certificates signed by a trusted CA are accepted.</description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.ssl.ciphers">
        <description>
          Constants for cipher selection
        </description>
        <item><name>SSL_CIPHERS_HIGH</name></item>
        <item><name>SSL_CIPHERS_MEDIUM</name></item>
        <item><name>SSL_CIPHERS_LOW</name></item>
        <item><name>SSL_CIPHERS_ALL</name></item>
        <item><name>SSL_CIPHERS_CUSTOM</name></item>
      </enum>
     <enum maturity="stable" id="enum.ssl.ciphers_tlsv1_3">
        <description>
          Constants for TLSv1.3 cipher selection
        </description>
        <item><name>TLSV1_3_CIPHERS_DEFAULT</name></item>
        <item><name>TLSV1_3_CIPHERS_CUSTOM</name></item>
      </enum>
     <enum maturity="stable" id="enum.ssl.shared_groups">
        <description>
          Constants for shared group selection
        </description>
        <item><name>TLS_SHARED_GROUPS_DEFAULT</name></item>
        <item><name>TLS_SHARED_GROUPS_CUSTOM</name></item>
      </enum>
      <enum maturity="stable" id="enum.ssl.hso">
        <description>
          Handshake order.
        </description>
        <item>
          <name>SSL_HSO_CLIENT_SERVER</name>
          <description>
                Perform the SSL-handshake with the client first.
          </description>
        </item>
        <item>
          <name>SSL_HSO_SERVER_CLIENT</name>
          <description>
                Perform the SSL-handshake with the server first.
          </description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.ssl.client_connection_security">
        <description>
          Client connection security type.
        </description>
        <item>
          <name>SSL_NONE</name>
          <description>
                Disable encryption between Zorp and the peer.
          </description>
        </item>
        <item>
          <name>SSL_FORCE_SSL</name>
          <description>
                Require encrypted communication between Zorp and the peer.
          </description>
        </item>
        <item>
          <name>SSL_ACCEPT_STARTTLS</name>
          <description>
                Permit STARTTLS sessions. Currently supported only in the Ftp and Smtp proxies.
          </description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.ssl.server_connection_security">
        <description>
          Server connection security type.
        </description>
        <item>
          <name>SSL_NONE</name>
          <description>
                Disable encryption between Zorp and the peer.
          </description>
        </item>
        <item>
          <name>SSL_FORCE_SSL</name>
          <description>
                Require encrypted communication between Zorp and the peer.
          </description>
        </item>
        <item>
          <name>SSL_FORWARD_STARTTLS</name>
          <description>
                Forward STARTTLS requests to the server. Currently supported only in the Ftp and Smtp proxies.
          </description>
        </item>
      </enum>
    </enums>
    <constants>
      <constantgroup maturity="stable" id="const.ssl.log">
        <description>
          Verbosity level of the log messages
        </description>
        <item>
          <name>SSL_ERROR</name>
          <description>
                Log only errors of the SSL framework.
          </description>
        </item>
        <item>
          <name>SSL_DEBUG</name>
          <description>
                Enable verbose logging of the SSL framework.
          </description>
        </item>
      </constantgroup>
      <constantgroup maturity="stable" id="const.ssl.hs">
        <description>
          Handshake policy decisions
        </description>
        <item>
          <name>SSL_HS_ACCEPT</name>
          <value>0</value>
          <description>
                Accept the connection.
          </description>
        </item>
        <item>
          <name>SSL_HS_REJECT</name>
          <value>1</value>
          <description>
                Reject the connection.
          </description>
        </item>
        <item>
          <name>SSL_HS_POLICY</name>
          <value>6</value>
          <description>
                Use a policy to decide about the connection.
          </description>
        </item>
        <item>
          <name>SSL_HS_VERIFIED</name>
          <value>10</value>
          <description>
                <!--FIXME-->
          </description>
        </item>
      </constantgroup>
    </constants>
    <actiontuples>
      <actiontuple maturity="stable" id="action.ssl.ciphers" action_enum="enum.ssl.ciphers">
        <description>
          Action codes for for cipher selection
        </description>
        <tuple action="SSL_CIPHERS_LOW" display_name="Low ciphers">
          <args/>
          <description>
            <para>
              Permit only the use of ciphers which use keys shorter then 128 bits.
            </para>
          </description>
        </tuple>
        <tuple action="SSL_CIPHERS_MEDIUM" display_name="Medium ciphers">
          <args/>
          <description>
            <para>
              Permit only the use of ciphers which use 128 bit long keys.
            </para>
          </description>
        </tuple>
        <tuple action="SSL_CIPHERS_HIGH" display_name="Low ciphers">
          <args/>
          <description>
            <para>
              Permit only the use of ciphers which use at least 128 bit long keys.
            </para>
          </description>
        </tuple>
        <tuple action="SSL_CIPHERS_ALL" display_name="All ciphers">
          <args/>
          <description>
            <para>
              Permit the use of all supported ciphers, including the 40 and 56 bit exportable ciphers.
            </para>
          </description>
        </tuple>
        <tuple action="SSL_CIPHERS_CUSTOM" display_name="Custom cipher">
          <args>
            <string display_name="Custom value"/>
          </args>
          <description>
            Permit only the use of ciphers which defined in value.
          </description>
        </tuple>
      </actiontuple>
      <actiontuple maturity="stable" id="action.ssl.ciphers_tlsv1_3" action_enum="enum.ssl.ciphers_tlsv1_3">
        <description>
          Action codes for for TLSv1.3 cipher selection
        </description>
        <tuple action="TLSV1_3_CIPHERS_DEFAULT" display_name="Default ciphers">
          <args/>
          <description>
            <para>
              Permit the use of OpenSSL's default supported ciphers.
            </para>
          </description>
        </tuple>
        <tuple action="TLSV1_3_CIPHERS_CUSTOM" display_name="Custom ciphers">
          <args>
            <string display_name="Custom value"/>
          </args>
          <description>
            Permit only the use of ciphers which defined in value.
          </description>
        </tuple>
      </actiontuple>
      <actiontuple maturity="stable" id="action.ssl.shared_groups" action_enum="enum.ssl.shared_groups">
        <description>
          Action codes for shared groups selection
        </description>
        <tuple action="TLS_SHARED_GROUPS_DEFAULT" display_name="Default shared groups">
          <args/>
          <description>
            <para>
              Permit the use of OpenSSL's default shared groups.
            </para>
          </description>
        </tuple>
        <tuple action="TLS_SHARED_GROUPS_CUSTOM" display_name="Custom shared groups">
          <args>
            <string display_name="Custom value"/>
          </args>
          <description>
            Permit only the use of shared groups which defined in value.
          </description>
        </tuple>
      </actiontuple>
    </actiontuples>
  </metainfo>
</module>
"""

import Globals
from Keybridge import X509KeyBridge
from Common import log
from Zorp import CORE_POLICY, CORE_DEBUG, CORE_ERROR, FALSE, TRUE
from Encryption_ import Encryption

import re, os

SSL_VERIFY_NONE                = 0
SSL_VERIFY_OPTIONAL            = 1
SSL_VERIFY_OPTIONAL_UNTRUSTED  = 1
SSL_VERIFY_OPTIONAL_TRUSTED    = 2
SSL_VERIFY_REQUIRED_UNTRUSTED  = 3
SSL_VERIFY_REQUIRED_TRUSTED    = 4

SSL_METHOD_SSLV23       = "SSLv23"
SSL_METHOD_SSLV3        = "SSLv3"
SSL_METHOD_TLSV1        = "TLSv1"
SSL_METHOD_TLSV1_1      = "TLSv1_1"
SSL_METHOD_TLSV1_2      = "TLSv1_2"
SSL_METHOD_ALL          = "SSLv23"

SSL_CIPHERS_ALL         = "ALL:!aNULL:@STRENGTH"

SSL_CIPHERS_HIGH        = "HIGH:!aNULL:@STRENGTH"
SSL_CIPHERS_MEDIUM      = "HIGH:MEDIUM:!aNULL:@STRENGTH"
SSL_CIPHERS_LOW         = "HIGH:MEDIUM:LOW:EXPORT:!aNULL:@STRENGTH"

SSL_CIPHERS_CUSTOM      = ""

TLSV1_3_CIPHERS_DEFAULT = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
TLSV1_3_CIPHERS_CUSTOM  = ""

TLS_SHARED_GROUPS_DEFAULT = "X25519:X448:P-521:P-384:P-256"
TLS_SHARED_GROUPS_CUSTOM  = ""

# connection security settings
SSL_NONE                = 0
SSL_FORCE_SSL           = 1
SSL_ACCEPT_STARTTLS     = 2
SSL_FORWARD_STARTTLS    = 3

# handshake order
SSL_HSO_CLIENT_SERVER   = 0
SSL_HSO_SERVER_CLIENT   = 1

SSL_ERROR      = 'core.error'
SSL_DEBUG      = 'core.debug'
SSL_INFO       = 'core.info'
SSL_VIOLATION  = 'core.violation'

# handshake policy decisions
SSL_HS_ACCEPT           = 1
SSL_HS_REJECT           = 3
SSL_HS_POLICY           = 6
SSL_HS_VERIFIED         = 10

class EncryptionPolicy(object):
    """
    <class maturity="stable" type="encryptionpolicy">
      <summary>Class encapsulating a named set of encryption settings.</summary>
      <description>
        <para>
          This class encapsulates a named set of encryption settings and an associated Encryption
          policy instance. Encryption policies provide a way to re-use
          encryption settings without having to define encryption settings
          for each service individually.
        </para>
      </description>
      <metainfo>
        <attributes>
          <attribute>
            <name>name</name>
            <type>
              <string/>
            </type>
            <description>Name identifying the Encryption policy.</description>
          </attribute>
          <attribute>
            <name>encryption</name>
            <type>
              <class filter="encryption" instance="yes"/>
            </type>
            <description>An encryption scenario instance that will be used in the Encryption Policy.
              <para>This describes the scenario and the settings how encryption is used in the scenario, for example:</para>
              <itemizedlist>
                <listitem>
                  <para>Both the client-side and the server-side connections are encrypted (<link linkend="python.Encryption.TwoSidedEncryption">TwoSidedEncryption</link>)</para>
                </listitem>
                <listitem>
                  <para>Only the client-side connection is encrypted (<link linkend="python.Encryption.ClientOnlyEncryption">ClientOnlyEncryption</link>)</para>
                </listitem>
                <listitem>
                  <para>Only the server-side connection is encrypted (<link linkend="python.Encryption.ServerOnlyEncryption">ServerOnlyEncryption</link>)</para>
                </listitem>
                <listitem>
                  <para>STARTTLS is enabled (<link linkend="python.Encryption.ClientOnlyStartTLSEncryption">ClientOnlyStartTLSEncryption</link>, <link linkend="python.Encryption.FakeStartTLSEncryption">FakeStartTLSEncryption</link>, or <link linkend="python.Encryption.ForwardStartTLSEncryption">ForwardStartTLSEncryption</link>)</para>
                </listitem>
              </itemizedlist>
              <para>To customize the settings of a scenario (for example, to set the used certificates), derive a class from the selected scenario, set its parameters as needed for your environment, and use the customized class.</para>
            </description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """

    def __init__(self, name, encryption):
        """
        <method maturity="stable">
          <summary>Constructor to create an Encryption policy.</summary>
          <description>
            <para>
              This constructor initializes an Encryption policy, based on the settings of the <parameter>encryption</parameter> parameter.
              This describes the scenario and the settings how encryption is used in the scenario, for example:</para>
              <itemizedlist>
                <listitem>
                  <para>Both the client-side and the server-side connections are encrypted (<link linkend="python.Encryption.TwoSidedEncryption">TwoSidedEncryption</link>)</para>
                </listitem>
                <listitem>
                  <para>Only the client-side connection is encrypted (<link linkend="python.Encryption.ClientOnlyEncryption">ClientOnlyEncryption</link>)</para>
                </listitem>
                <listitem>
                  <para>Only the server-side connection is encrypted (<link linkend="python.Encryption.ServerOnlyEncryption">ServerOnlyEncryption</link>)</para>
                </listitem>
                <listitem>
                  <para>STARTTLS is enabled (<link linkend="python.Encryption.ClientOnlyStartTLSEncryption">ClientOnlyStartTLSEncryption</link>, <link linkend="python.Encryption.FakeStartTLSEncryption">FakeStartTLSEncryption</link>, or <link linkend="python.Encryption.ForwardStartTLSEncryption">ForwardStartTLSEncryption</link>)</para>
                </listitem>
              </itemizedlist>
              <para>To customize the settings of a scenario (for example, to set the used certificates), derive a class from the selected scenario, set its parameters as needed for your environment, and use the customized class.</para>
          </description>
          <metainfo>
            <arguments>
              <argument>
                <name>name</name>
                <type>
                  <string/>
                </type>
                <description>Name identifying the Encryption policy.</description>
              </argument>
              <argument>
                <name>encryption</name>
                <type>
                  <class filter="encryption" instance="yes"/>
                </type>
                <description>An encryption scenario instance that will be used in the Encryption Policy.</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        self.name = name
        self.encryption = encryption

        if Globals.encryption_policies.has_key(name):
            raise ValueError, "Duplicate encryption policy name; name='%s'" % name
        Globals.encryption_policies[name] = self

    def getEncryption(self):
        """
        <method internal="yes"/>
        """
        return self.encryption

class NoneEncryption(Encryption):
    """
    <class internal="yes"/>
    """
    def __init__(self):
        super(NoneEncryption, self).__init__(client_security = SSL_NONE, server_security = SSL_NONE)

def getEncryptionPolicy(name):
    """
    <function internal="yes"/>
    """
    if name:
        if Globals.encryption_policies.has_key(name):
            return Globals.encryption_policies[name]
        else:
            log(None, CORE_POLICY, 3, "No such encryption policy; name='%s'", name)
    return None

def readPEM(filename):
    """<function internal="yes"/>
    """
    log(None, CORE_DEBUG, 6, "Reading PEM file; filename='%s'" % filename)
    f = open(filename, 'r')
    res = f.read()
    f.close()
    return res

class SSLOptions(object):
    """
    <class maturity="stable" abstract="yes">
      <summary>
        Class encapsulating the abstract SSL options.
      </summary>
      <description>
        <para>This class collects the TLS and SSL settings directly related
        to encryption, for example, the permitted protocol versions, ciphers,
        session reuse settings, and so on.
        Note that you cannot use this class directly, use an appropriate derived class,
        for example, <link linkend="python.Encryption.ClientSSLOptions">ClientSSLOptions</link>
        or <link linkend="python.Encryption.ServerSSLOptions">ServerSSLOptions</link> instead.
        </para>
      </description>
      <metainfo>


        <attributes>
          <attribute>
            <name>cipher</name>
            <type>
              <hash>
                <key>
                  <string display_name="SSL cipher type"/>
                </key>
                <value>
                  <link id="action.ssl.ciphers"/>
                </value>
              </hash>
            </type>
            <description>Specifies the allowed ciphers.
            For details, see <xref linkend="action.ssl.ciphers"/>.</description>
          </attribute>
          <attribute>
            <name>ciphers_tlsv1_3</name>
            <type>
              <hash>
                <key>
                  <string display_name="TLSv1.3 cipher type"/>
                </key>
                <value>
                  <link id="action.ssl.ciphers_tlsv1_3"/>
                </value>
              </hash>
            </type>
            <description>Specifies the allowed ciphers for TLSv1.3 connections.
            For details, see <xref linkend="action.ssl.ciphers_tlsv1_3"/>.</description>
          </attribute>
          <attribute>
            <name>shared_groups</name>
            <type>
              <hash>
                <key>
                  <string display_name="TLS shared group type"/>
                </key>
                <value>
                  <link id="action.ssl.shared_groups"/>
                </value>
              </hash>
            </type>
            <description>Specifies the allowed shared groups.
            For details, see <xref linkend="action.ssl.shared_groups"/>.</description>
          </attribute>
          <attribute>
            <name>disable_tlsv1</name>
            <type>
              <boolean/>
            </type>
            <default>TRUE</default>
            <description>Do not allow using TLSv1 in the connection.</description>
          </attribute>
          <attribute>
            <name>disable_tlsv1_1</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <description>Do not allow using TLSv1.1 in the connection.</description>
          </attribute>
          <attribute>
            <name>disable_tlsv1_2</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <description>Do not allow using TLSv1.2 in the connection.</description>
          </attribute>
          <attribute>
            <name>disable_tlsv1_3</name>
            <type>
              <boolean/>
            </type>
            <default>TRUE</default>
            <description>Do not allow using TLSv1.3 in the connection.</description>
          </attribute>
          <attribute>
            <name>disable_compression</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <description>Set this to TRUE to disable support for SSL/TLS compression even if it is supported. Please be mind that this option is ignored in TLSv1.3 as it does not support compression.</description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """

    def __init__(self, cipher=SSL_CIPHERS_HIGH, ciphers_tlsv1_3=TLSV1_3_CIPHERS_DEFAULT,
                       shared_groups=TLS_SHARED_GROUPS_DEFAULT, timeout=300,
                       disable_tlsv1=False, disable_tlsv1_1=False, disable_tlsv1_2=False, disable_tlsv1_3=True,
                       disable_compression=False):
        """
        <method maturity="stable">
          <summary>
            Constructor to initialize an SSLOptions instance.
          </summary>
          <description>
            <para>
              This constructor defines an SSLOptions with the specified parameters.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>cipher</name>
                <type>
                  <link id="action.ssl.ciphers"/>
                </type>
                <description>Specifies the allowed ciphers.
                For details, see <xref linkend="action.ssl.ciphers"/>.</description>
              </argument>
              <argument maturity="stable">
                <name>ciphers_tlsv1_3</name>
                <type>
                  <link id="action.ssl.ciphers_tlsv1_3"/>
                </type>
                <description>Specifies the allowed ciphers for TLSv1.3 connections.
                For details, see <xref linkend="action.ssl.ciphers_tlsv1_3"/>.</description>
              </argument>
              <argument maturity="stable">
                <name>shared_groups</name>
                <type>
                  <link id="action.ssl.shared_groups"/>
                </type>
                <description>Specifies the allowed shared groups.
                For details, see <xref linkend="action.ssl.shared_groups"/>.</description>
              </argument>
              <argument maturity="stable">
                <name>timeout</name>
                <type>
                  <integer/>
                </type>
                <default>300</default>
                <description>Drop idle connection if the timeout value (in seconds) expires.</description>
              </argument>
              <argument maturity="stable">
                <name>disable_tlsv1</name>
                <type>
                  <boolean/>
                </type>
                <default>TRUE</default>
                <description>Do not allow using TLSv1 in the connection.</description>
              </argument>
              <argument maturity="stable">
                <name>disable_tlsv1_1</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <description>Do not allow using TLSv1.1 in the connection.</description>
              </argument>
              <argument maturity="stable">
                <name>disable_tlsv1_2</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <description>Do not allow using TLSv1.2 in the connection.</description>
              </argument>
              <argument maturity="stable">
                <name>disable_tlsv1_3</name>
                <type>
                  <boolean/>
                </type>
                <default>TRUE</default>
                <description>Do not allow using TLSv1.3 in the connection.</description>
              </argument>
              <argument maturity="stable">
                <name>disable_compression</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <description>Set this to TRUE to disable support for SSL/TLS compression even if it is supported. Please be mind that this option is ignored in TLSv1.3 as it does not support compression.</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """

        self.cipher = cipher[1] if isinstance(cipher, tuple) else cipher
        self.ciphers_tlsv1_3 = ciphers_tlsv1_3[1] if isinstance(ciphers_tlsv1_3, tuple) else ciphers_tlsv1_3
        self.shared_groups = shared_groups[1] if isinstance(shared_groups, tuple) else shared_groups
        self.timeout = timeout
        self.disable_tlsv1 = disable_tlsv1
        self.disable_tlsv1_1 = disable_tlsv1_1
        self.disable_tlsv1_2 = disable_tlsv1_2
        self.disable_tlsv1_3 = disable_tlsv1_3
        self.disable_compression = disable_compression

    def setup(self, encryption):
        """
        <method internal="yes"/>
        """
        pass

class ClientSSLOptions(SSLOptions):
    """
    <class type="clientssloptions">
    <summary>
        Class encapsulating a set of SSL options used in the client-side connection.
      </summary>
      <description>
        <para>This class (based on the SSLOptions class) collects the TLS and SSL settings directly related
        to encryption, for example, the permitted protocol versions, ciphers,
        session reuse settings, and so on.
        </para>
      </description>
      <metainfo>
        <attributes>
          <attribute>
            <name>cipher</name>
            <type>
              <link id="action.ssl.ciphers"/>
            </type>
            <description>Specifies the allowed ciphers.
            For details, see <xref linkend="action.ssl.ciphers"/>.</description>
          </attribute>
          <attribute>
            <name>cipher</name>
            <type>
              <link id="action.ssl.ciphers_tlsv1_3"/>
            </type>
            <description>Specifies the allowed ciphers for TLSv1.3 connections.
            For details, see <xref linkend="action.ssl.ciphers_tlsv1_3"/>.</description>
          </attribute>
          <attribute>
            <name>shared_groups</name>
            <type>
              <link id="action.ssl.shared_groups"/>
            </type>
            <description>Specifies the allowed shared groups.
            For details, see <xref linkend="action.ssl.shared_groups"/>.</description>
          </attribute>
          <attribute>
            <name>cipher_server_preference</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <description>Use server and not client preference order when determining which cipher suite, signature algorithm or elliptic curve to use for an incoming connection.</description>
          </attribute>
          <attribute>
            <name>disable_tlsv1</name>
            <type>
              <boolean/>
            </type>
            <default>TRUE</default>
            <description>Do not allow using TLSv1 in the connection.</description>
          </attribute>
          <attribute>
            <name>disable_tlsv1_1</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <description>Do not allow using TLSv1.1 in the connection.</description>
          </attribute>
          <attribute>
            <name>disable_tlsv1_2</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <description>Do not allow using TLSv1.2 in the connection.</description>
          </attribute>
          <attribute>
            <name>disable_tlsv1_3</name>
            <type>
              <boolean/>
            </type>
            <default>TRUE</default>
            <description>Do not allow using TLSv1.3 in the connection.</description>
          </attribute>
          <attribute>
            <name>disable_compression</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <description>Set this to TRUE to disable support for SSL/TLS compression even if it is supported. Please be mind that this option is ignored in TLSv1.3 as it does not support compression.</description>
          </attribute>
          <attribute>
            <name>dh_params</name>
            <type>
              <dhparams/>
            </type>
            <default>None</default>
            <description>
             The DH parameter used by ephemeral DH key generarion. Please be mind that this option is ignored in TLSv1.3 as it does not support custom DH parameters.
            </description>
          </attribute>
          <attribute>
            <name>disable_send_root_ca</name>
            <type>
              <boolean/>
            </type>
            <default>False</default>
            <description>
             Inhibit sending Root CA to client, even if present in local certificate chain.
            </description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """

    def __init__(self, method=SSL_METHOD_ALL, cipher=SSL_CIPHERS_HIGH, ciphers_tlsv1_3=TLSV1_3_CIPHERS_DEFAULT,
                       shared_groups=TLS_SHARED_GROUPS_DEFAULT, cipher_server_preference=False, timeout=300,
                       disable_sslv2=True, disable_sslv3=True,
                       disable_tlsv1=False, disable_tlsv1_1=False, disable_tlsv1_2=False, disable_tlsv1_3=True,
                       disable_compression=False, dh_params=None, disable_renegotiation=True, disable_send_root_ca=False):
        """
        <method maturity="stable">
          <summary>
            Constructor to initialize a ClientSSLOptions instance.
          </summary>
          <description>
            <para>
              This constructor defines a ClientSSLOptions with the specified parameters.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>cipher</name>
                <type>
                  <link id="action.ssl.ciphers"/>
                </type>
                <description>Specifies the allowed ciphers.
                For details, see <xref linkend="action.ssl.ciphers"/>.</description>
              </argument>
              <argument maturity="stable">
                <name>ciphers_tlsv1_3</name>
                <type>
                  <link id="action.ssl.ciphers_tlsv1_3"/>
                </type>
                <description>Specifies the allowed ciphers for TLSv1.3 connections.
                For details, see <xref linkend="action.ssl.ciphers_tlsv1_3"/>.</description>
              </argument>
              <argument maturity="stable">
                <name>shared_groups</name>
                <type>
                  <link id="action.ssl.shared_groups"/>
                </type>
                <description>Specifies the allowed shared groups.
                For details, see <xref linkend="action.ssl.shared_groups"/>.</description>
              </argument>
              <argument maturity="stable">
                <name>cipher_server_preference</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <description>Use server and not client preference order when determining which cipher suite, signature algorithm or elliptic curve to use for an incoming connection.</description>
              </argument>
              <argument maturity="stable">
                <name>timeout</name>
                <type>
                  <integer/>
                </type>
                <default>300</default>
                <description>Drop idle connection if the timeout value (in seconds) expires.</description>
              </argument>
              <argument maturity="stable">
                <name>disable_tlsv1</name>
                <type>
                  <boolean/>
                </type>
                <default>TRUE</default>
                <description>Do not allow using TLSv1 in the connection.</description>
              </argument>
              <argument maturity="stable">
                <name>disable_tlsv1_1</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <description>Do not allow using TLSv1.1 in the connection.</description>
              </argument>
              <argument maturity="stable">
                <name>disable_tlsv1_2</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <description>Do not allow using TLSv1.2 in the connection.</description>
              </argument>
              <argument maturity="stable">
                <name>disable_tlsv1_3</name>
                <type>
                  <boolean/>
                </type>
                <default>TRUE</default>
                <description>Do not allow using TLSv1.3 in the connection.</description>
              </argument>
              <argument maturity="stable">
                <name>disable_compression</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <description>Set this to TRUE to disable support for SSL/TLS compression even if it is supported. Please be mind that this option is ignored in TLSv1.3 as it does not support compression.</description>
              </argument>
              <argument>
                <name>dh_param_file_path</name>
                <type>
                  <string/>
                </type>
                <default>None</default>
                <description>
                 The path and filename to the DH parameter file. The DH parameter file must be in PEM format. Please be mind that this option is ignored in TLSv1.3 as it does not support custom DH parameters.
                </description>
              </argument>
              <argument maturity="stable">
                <name>disable_renegotiation</name>
                <type>
                  <boolean/>
                </type>
                <default>TRUE</default>
                <description>Set this to TRUE to disable client initiated renegotiation. Please be mind that this option is ignored in TLSv1.3 as it does not support renegotiation.</description>
              </argument>
              <argument maturity="stable">
                <name>disable_send_root_ca</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <description>Set this to TRUE to inhibit sending root ca to client, even if present in local chain.</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """

        super(ClientSSLOptions, self).__init__(cipher, ciphers_tlsv1_3, shared_groups, timeout,
                                               disable_tlsv1, disable_tlsv1_1, disable_tlsv1_2, disable_tlsv1_3,
                                               disable_compression)
        self.cipher_server_preference = cipher_server_preference
        if dh_params is None:
            self.dh_params = ""
        elif isinstance(dh_params, DHParam):
            self.dh_params = dh_params.getParams()
        elif isinstance(dh_params, str):
            self.dh_params = dh_params
        else:
            raise TypeError, "Type of dh_params must be string or DHParam"
        self.disable_renegotiation = disable_renegotiation
        self.disable_send_root_ca = disable_send_root_ca

    def setup(self, encryption):
        """
        <method internal="yes"/>
        """
        super(ClientSSLOptions, self).setup(encryption)
        encryption.settings.client_disable_proto_tlsv1 = self.disable_tlsv1
        encryption.settings.client_disable_proto_tlsv1_1 = self.disable_tlsv1_1
        encryption.settings.client_disable_proto_tlsv1_2 = self.disable_tlsv1_2
        encryption.settings.client_disable_proto_tlsv1_3 = self.disable_tlsv1_3
        encryption.settings.client_disable_compression = self.disable_compression
        encryption.settings.client_ssl_cipher = self.cipher
        encryption.settings.client_ciphers_tlsv1_3 = self.ciphers_tlsv1_3
        encryption.settings.client_shared_groups = self.shared_groups
        encryption.settings.cipher_server_preference = self.cipher_server_preference
        encryption.settings.dh_params = self.dh_params
        encryption.settings.disable_renegotiation = self.disable_renegotiation
        encryption.settings.client_disable_send_root_ca = self.disable_send_root_ca

class ServerSSLOptions(SSLOptions):
    """
    <class type="serverssloptions">
    <summary>
        Class encapsulating a set of SSL options used in the server-side connection.
      </summary>
      <description>
        <para>This class (based on the SSLOptions class) collects the TLS and SSL settings directly related
        to encryption, for example, the permitted protocol versions, ciphers,
        session reuse settings, and so on.
        </para>
      </description>
      <metainfo>
        <attributes>
          <attribute>
            <name>cipher</name>
            <type>
              <link id="action.ssl.ciphers"/>
            </type>
            <description>Specifies the allowed ciphers.
            For details, see <xref linkend="action.ssl.ciphers"/>.</description>
          </attribute>
          <attribute>
            <name>ciphers_tlsv1_3</name>
            <type>
              <link id="action.ssl.ciphers_tlsv1_3"/>
            </type>
            <description>Specifies the allowed ciphers for TLSv1.3 connections.
            For details, see <xref linkend="action.ssl.ciphers_tlsv1_3"/>.</description>
          </attribute>
          <attribute>
            <name>shared_groups</name>
            <type>
              <link id="action.ssl.shared_groups"/>
            </type>
            <description>Specifies the allowed shared groups.
            For details, see <xref linkend="action.ssl.shared_groups"/>.</description>
          </attribute>
          <attribute>
            <name>disable_tlsv1</name>
            <type>
              <boolean/>
            </type>
            <default>TRUE</default>
            <description>Do not allow using TLSv1 in the connection.</description>
          </attribute>
          <attribute>
            <name>disable_tlsv1_1</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <description>Do not allow using TLSv1.1 in the connection.</description>
          </attribute>
          <attribute>
            <name>disable_tlsv1_2</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <description>Do not allow using TLSv1.2 in the connection.</description>
          </attribute>
          <attribute>
            <name>disable_tlsv1_3</name>
            <type>
              <boolean/>
            </type>
            <default>TRUE</default>
            <description>Do not allow using TLSv1.3 in the connection.</description>
          </attribute>
          <attribute>
            <name>disable_compression</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <description>Set this to TRUE to disable support for SSL/TLS compression even if it is supported. Please be mind that this option is ignored in TLSv1.3 as it does not support compression.</description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """

    def __init__(self, method=SSL_METHOD_ALL, cipher=SSL_CIPHERS_HIGH, ciphers_tlsv1_3=TLSV1_3_CIPHERS_DEFAULT,
                       shared_groups=TLS_SHARED_GROUPS_DEFAULT, timeout=300,
                       disable_sslv2=True, disable_sslv3=True,
                       disable_tlsv1=False, disable_tlsv1_1=False, disable_tlsv1_2=False, disable_tlsv1_3=True,
                       disable_compression=False):
        """
        <method maturity="stable">
          <summary>
            Constructor to initialize a ServerSSLOptions instance.
          </summary>
          <description>
            <para>
              This constructor defines a ServerSSLOptions with the specified parameters.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>cipher</name>
                <type>
                  <link id="action.ssl.ciphers"/>
                </type>
                <description>Specifies the allowed ciphers.
                For details, see <xref linkend="action.ssl.ciphers"/>.</description>
              </argument>
              <argument maturity="stable">
                <name>ciphers_tlsv1_3</name>
                <type>
                  <link id="action.ssl.ciphers_tlsv1_3"/>
                </type>
                <description>Specifies the allowed ciphers for TLSv1.3 connections.
                For details, see <xref linkend="action.ssl.ciphers_tlsv1_3"/>.</description>
              </argument>
              <argument maturity="stable">
                <name>shared_groups</name>
                <type>
                  <link id="action.ssl.shared_groups"/>
                </type>
                <description>Specifies the allowed shared groups.
                For details, see <xref linkend="action.ssl.shared_groups"/>.</description>
              </argument>
              <argument maturity="stable">
                <name>timeout</name>
                <type>
                  <integer/>
                </type>
                <default>300</default>
                <description>Drop idle connection if the timeout value (in seconds) expires.</description>
              </argument>
              <argument maturity="stable">
                <name>disable_tlsv1</name>
                <type>
                  <boolean/>
                </type>
                <default>TRUE</default>
                <description>Do not allow using TLSv1 in the connection.</description>
              </argument>
              <argument maturity="stable">
                <name>disable_tlsv1_1</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <description>Do not allow using TLSv1.1 in the connection.</description>
              </argument>
              <argument maturity="stable">
                <name>disable_tlsv1_2</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <description>Do not allow using TLSv1.2 in the connection.</description>
              </argument>
              <argument maturity="stable">
                <name>disable_tlsv1_3</name>
                <type>
                  <boolean/>
                </type>
                <default>TRUE</default>
                <description>Do not allow using TLSv1.3 in the connection.</description>
              </argument>
              <argument maturity="stable">
                <name>disable_compression</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <description>Set this to TRUE to disable support for SSL/TLS compression even if it is supported. Please be mind that this option is ignored in TLSv1.3 as it does not support compression.</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """

        super(ServerSSLOptions, self).__init__(cipher, ciphers_tlsv1_3, shared_groups, timeout,
                                               disable_tlsv1, disable_tlsv1_1, disable_tlsv1_2, disable_tlsv1_3,
                                               disable_compression)

    def setup(self, encryption):
        """
        <method internal="yes"/>
        """
        super(ServerSSLOptions, self).setup(encryption)
        encryption.settings.server_disable_proto_tlsv1 = self.disable_tlsv1
        encryption.settings.server_disable_proto_tlsv1_1 = self.disable_tlsv1_1
        encryption.settings.server_disable_proto_tlsv1_2 = self.disable_tlsv1_2
        encryption.settings.server_disable_proto_tlsv1_3 = self.disable_tlsv1_3
        encryption.settings.server_disable_compression = self.disable_compression
        encryption.settings.server_ssl_cipher = self.cipher
        encryption.settings.server_ciphers_tlsv1_3 = self.ciphers_tlsv1_3
        encryption.settings.server_shared_groups = self.shared_groups

class AbstractVerifier(object):
    """
    <class maturity="stable" abstract="yes">
      <summary>
        Class encapsulating the abstract Certificate verifier.
      </summary>
      <description>
        <para>This class includes the settings and options used to verify the certificates of the peers in SSL and TLS connections.
         Note that you cannot use this class directly, use an appropriate derived class,
         for example, <link linkend="python.Encryption.ClientCertificateVerifier">ClientCertificateVerifier</link>
         or <link linkend="python.Encryption.ServerCertificateVerifier">ServerCertificateVerifier</link> instead.</para>
      </description>
      <metainfo>
        <attributes>
            <attribute state="stable">
                <name>trusted_certs_directory</name>
                <type>
                  <string/>
                </type>
                <default>""</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  A directory where trusted IP address - certificate assignments are
                  stored. When a peer from a specific IP address shows the
                  certificate stored in this directory, it is accepted regardless of
                  its expiration or issuer CA. Each file in the directory should
                  contain a certificate in PEM format. The filename must bethe IP
                  address.
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>required</name>
                <default>trusted</default>
                <type>
                  <boolean/>
                </type>
                <default>TRUE</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  If the <parameter>required</parameter> is TRUE, Zorp requires a certificate from the peer.
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>trusted</name>
                <default>TRUE</default>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  If the peer shows a certificate and the <parameter>trusted</parameter> parameter is TRUE, only certificates signed by a trusted CA are accepted.
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>verify_depth</name>
                <type>
                  <integer/>
                </type>
                <default>4</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  The length of the longest accepted CA verification chain. Zorp will automatically reject longer CA chains.
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>verify_ca_directory</name>
                <type>
                  <string/>
                </type>
                <default>""</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Directory where the trusted CA certificates are stored. CA certificates are loaded
                  on-demand from this directory when Zorp verifies the certificate of the peer.
                  <para>Available only in Zorp version 3.4.3 and later.</para>
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>verify_crl_directory</name>
                <type>
                  <string/>
                </type>
                <default>""</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Directory where the CRLs (Certificate Revocation Lists) associated with trusted CAs are stored. CRLs are loaded
                  on-demand from this directory when Zorp verifies the certificate of the peer.
                  <para>Available only in Zorp version 3.4.3 and later.</para>
                </description>
            </attribute>
            <attribute>
                <name>permit_invalid_certificates</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  When <parameter>permit_invalid_certificates</parameter> is TRUE and <parameter>trusted</parameter> is FALSE, Zorp accepts even invalid certificates, for example, expired or self-signed certificates.
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>permit_missing_crl</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  This option has effect only if the <parameter>verify_crl_directory</parameter> parameter is set. If Zorp does not find a CRL in these directories that matches the CAs in the certificate chain and <parameter>permit_missing_crl</parameter> is set to FALSE, Zorp rejects the certificate. Otherwise, the certificate is accepted even if no matching CRL is found.
                  <para>Available only in Zorp version 3.4.3 and later.</para>
                </description>
            </attribute>
        </attributes>
      </metainfo>
    </class>
    """

    def __init__(self, trusted_certs_directory=None, required=True, trusted=True, verify_depth=4, verify_ca_directory=None, verify_crl_directory=None, permit_invalid_certificates=False, permit_missing_crl=False):
        """
        <method maturity="stable">
          <summary>
            Constructor to initialize an AbstractVerifier instance.
          </summary>
          <description>
            <para>
              This constructor defines an AbstractVerifier with the specified parameters.
            </para>
          </description>
          <metainfo>
            <arguments>
                <argument state="stable">
                    <name>trusted_certs_directory</name>
                    <type>
                      <string/>
                    </type>
                    <default>""</default>
                    <description>
                      A directory where trusted IP address - certificate assignments are
                      stored. When a peer from a specific IP address shows the
                      certificate stored in this directory, it is accepted regardless of
                      its expiration or issuer CA. Each file in the directory should
                      contain a certificate in PEM format. The filename must bethe IP
                      address.
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>required</name>
                    <default>TRUE</default>
                    <type>
                      <boolean/>
                    </type>
                    <description>
                      If the <parameter>required</parameter> is TRUE, Zorp requires a certificate from the peer.
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>trusted</name>
                    <default>TRUE</default>
                    <type>
                      <boolean/>
                    </type>
                    <default>FALSE</default>
                    <description>
                      If the peer shows a certificate and the <parameter>trusted</parameter> parameter is TRUE, only certificates signed by a trusted CA are accepted.
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>verify_depth</name>
                    <type>
                      <integer/>
                    </type>
                    <default>4</default>
                    <description>
                      The length of the longest accepted CA verification chain. Zorp will automatically reject longer CA chains.
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>verify_ca_directory</name>
                    <type>
                      <string/>
                    </type>
                    <default>""</default>
                    <description>
                      Directory where the trusted CA certificates are stored. CA certificates are loaded
                      on-demand from this directory when Zorp verifies the certificate of the peer.
                      <para>Available only in Zorp version 3.4.3 and later.</para>
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>verify_crl_directory</name>
                    <type>
                      <string/>
                    </type>
                    <default>""</default>
                    <description>
                      Directory where the CRLs (Certificate Revocation Lists) associated with trusted CAs are stored. CRLs are loaded
                      on-demand from this directory when Zorp verifies the certificate of the peer.
                      <para>Available only in Zorp version 3.4.3 and later.</para>
                    </description>
                </argument>
                <argument>
                    <name>permit_invalid_certificates</name>
                    <type>
                      <boolean/>
                    </type>
                    <default>FALSE</default>
                    <description>
                      When <parameter>permit_invalid_certificates</parameter> is TRUE and <parameter>trusted</parameter> is FALSE, Zorp accepts even invalid certificates, for example, expired or self-signed certificates.
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>permit_missing_crl</name>
                    <type>
                      <boolean/>
                    </type>
                    <default>FALSE</default>
                    <description>
                      This option has effect only if the <parameter>verify_crl_directory</parameter> parameter is set. If Zorp does not find a CRL in these directories that matches the CAs in the certificate chain and <parameter>permit_missing_crl</parameter> is set to FALSE, Zorp rejects the certificate. Otherwise, the certificate is accepted even if no matching CRL is found.
                      <para>Available only in Zorp version 3.4.3 and later.</para>
                    </description>
                </argument>
            </arguments>
          </metainfo>
        </method>
        """
        self.trusted_certs_directory=trusted_certs_directory
        self.required=required
        self.trusted=trusted
        self.verify_depth=verify_depth
        self.verify_ca_directory=verify_ca_directory
        self.verify_crl_directory=verify_crl_directory
        self.permit_invalid_certificates=permit_invalid_certificates
        self.permit_missing_crl=permit_missing_crl

    def setup(self, encryption):
        """
        <method internal="yes"/>
        """
        pass

    def setup_verify_type(self):
        """
        <method internal="yes"/>
        """
        if self.required == False and self.trusted == False:
            return SSL_VERIFY_OPTIONAL_UNTRUSTED
        elif self.required ==True and self.trusted == False:
            return SSL_VERIFY_REQUIRED_UNTRUSTED
        elif self.required == False and self.trusted == True:
            return SSL_VERIFY_OPTIONAL_TRUSTED
        elif self.required == True and self.trusted == True:
            return SSL_VERIFY_REQUIRED_TRUSTED
        else:
            raise ValueError, "Required and trusted parameters must be True or False"

    def verify(self):
        """
        <method internal="yes"/>
        """
        raise NotImplementedError

class ClientCertificateVerifier(AbstractVerifier):
    """
    <class type="clientcertificateverifier">
      <summary>
        Class that can be used to verify the certificate of the client-side connection.
      </summary>
      <description>
        <para>This class includes the settings and options used to verify the certificates of the peers in client-side SSL and TLS connections.</para>
      </description>
      <metainfo>
        <attributes>
            <attribute state="stable">
                <name>trusted_certs_directory</name>
                <type>
                  <string/>
                </type>
                <default>""</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  A directory where trusted IP address - certificate assignments are
                  stored. When a peer from a specific IP address shows the
                  certificate stored in this directory, it is accepted regardless of
                  its expiration or issuer CA. Each file in the directory should
                  contain a certificate in PEM format. The filename must bethe IP
                  address.
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>required</name>
                <type>
                  <boolean/>
                </type>
                <default>TRUE</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  If the <parameter>required</parameter> is TRUE, Zorp requires a certificate from the peer.
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>trusted</name>
                <default>TRUE</default>
                <type>
                  <boolean/>
                </type>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  If the peer shows a certificate and the <parameter>trusted</parameter> parameter is TRUE, only certificates signed by a trusted CA are accepted.
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>verify_depth</name>
                <type>
                  <integer/>
                </type>
                <default>4</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  The length of the longest accepted CA verification chain. Zorp will automatically reject longer CA chains.
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>verify_ca_directory</name>
                <type>
                  <string/>
                </type>
                <default>""</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Directory where the trusted CA certificates are stored. CA certificates are loaded
                  on-demand from this directory when Zorp verifies the certificate of the peer.
                  <para>Available only in Zorp version 3.4.3 and later.</para>
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>verify_crl_directory</name>
                <type>
                  <string/>
                </type>
                <default>""</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Directory where the CRLs (Certificate Revocation Lists) associated with trusted CAs are stored. CRLs are loaded
                  on-demand from this directory when Zorp verifies the certificate of the peer.
                  <para>Available only in Zorp version 3.4.3 and later.</para>
                </description>
            </attribute>
            <attribute>
                <name>permit_invalid_certificates</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  When <parameter>permit_invalid_certificates</parameter> is TRUE and <parameter>trusted</parameter> is FALSE, Zorp accepts even invalid certificates, for example, expired or self-signed certificates.
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>permit_missing_crl</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  This option has effect only if the <parameter>verify_crl_directory</parameter> parameter is set. If Zorp does not find a CRL in these directories that matches the CAs in the certificate chain and <parameter>permit_missing_crl</parameter> is set to FALSE, Zorp rejects the certificate. Otherwise, the certificate is accepted even if no matching CRL is found.
                  <para>Available only in Zorp version 3.4.3 and later.</para>
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>ca_hint_directory</name>
                <type>
                  <string/>
                </type>
                <default>""</default>
                <description>
                  Set directory containing certificates to provide the client the list of CA certificates (subject names) that are used for verifying the client certificate.
                </description>
            </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    def __init__(self, trusted_certs_directory=None, required=True, trusted=True, verify_depth=4, verify_ca_directory=None, verify_crl_directory=None, permit_invalid_certificates=False, permit_missing_crl=False, ca_hint_directory=None):
        """
        <method maturity="stable">
          <summary>
            Constructor to initialize a ClientCertificateVerifier instance.
          </summary>
          <description>
            <para>
              This constructor defines a ClientCertificateVerifier with the specified parameters.
            </para>
          </description>
          <metainfo>
            <arguments>
                <argument state="stable">
                    <name>trusted_certs_directory</name>
                    <type>
                      <string/>
                    </type>
                    <default>""</default>
                    <description>
                      A directory where trusted IP address - certificate assignments are
                      stored. When a peer from a specific IP address shows the
                      certificate stored in this directory, it is accepted regardless of
                      its expiration or issuer CA. Each file in the directory should
                      contain a certificate in PEM format. The filename must bethe IP
                      address.
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>required</name>
                    <default>TRUE</default>
                    <type>
                      <boolean/>
                    </type>
                    <description>
                      If the <parameter>required</parameter> is TRUE, Zorp requires a certificate from the peer.
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>trusted</name>
                    <default>TRUE</default>
                    <type>
                      <boolean/>
                    </type>
                    <description>
                      If the peer shows a certificate and the <parameter>trusted</parameter> parameter is TRUE, only certificates signed by a trusted CA are accepted.
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>verify_depth</name>
                    <type>
                      <integer/>
                    </type>
                    <default>4</default>
                    <description>
                      The length of the longest accepted CA verification chain. Zorp will automatically reject longer CA chains.
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>verify_ca_directory</name>
                    <type>
                      <string/>
                    </type>
                    <default>""</default>
                    <description>
                      Directory where the trusted CA certificates are stored. CA certificates are loaded
                      on-demand from this directory when Zorp verifies the certificate of the peer.
                      <para>Available only in Zorp version 3.4.3 and later.</para>
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>verify_crl_directory</name>
                    <type>
                      <string/>
                    </type>
                    <default>""</default>
                    <description>
                      Directory where the CRLs (Certificate Revocation Lists) associated with trusted CAs are stored. CRLs are loaded
                      on-demand from this directory when Zorp verifies the certificate of the peer.
                      <para>Available only in Zorp version 3.4.3 and later.</para>
                    </description>
                </argument>
                <argument>
                    <name>permit_invalid_certificates</name>
                    <type>
                      <boolean/>
                    </type>
                    <default>FALSE</default>
                    <description>
                      When <parameter>permit_invalid_certificates</parameter> is TRUE and <parameter>trusted</parameter> is FALSE, Zorp accepts even invalid certificates, for example, expired or self-signed certificates.
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>permit_missing_crl</name>
                    <type>
                      <boolean/>
                    </type>
                    <default>FALSE</default>
                    <description>
                      This option has effect only if the <parameter>verify_crl_directory</parameter> parameter is set. If Zorp does not find a CRL in these directories that matches the CAs in the certificate chain and <parameter>permit_missing_crl</parameter> is set to FALSE, Zorp rejects the certificate. Otherwise, the certificate is accepted even if no matching CRL is found.
                      <para>Available only in Zorp version 3.4.3 and later.</para>
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>ca_hint_directory</name>
                    <type>
                      <string/>
                    </type>
                    <default>""</default>
                    <description>
                      Set directory containing certificates to provide the client the list of CA certificates (subject names) that are used for verifying the client certificate.
                    </description>
                </argument>
            </arguments>
          </metainfo>
        </method>
        """

        super(ClientCertificateVerifier, self).__init__(trusted_certs_directory, required, trusted, verify_depth, verify_ca_directory, verify_crl_directory, permit_invalid_certificates, permit_missing_crl)

        self.ca_hint_directory = ca_hint_directory

    def setup(self, encryption):
        """
        <method internal="yes"/>
        """
        super(ClientCertificateVerifier, self).setup(encryption)

        encryption.settings.client_verify_type = self.setup_verify_type()

        encryption.settings.client_max_verify_depth = self.verify_depth
        encryption.settings.client_permit_invalid_certificates = self.permit_invalid_certificates
        encryption.settings.client_permit_missing_crl = self.permit_missing_crl

        if self.verify_ca_directory:
            encryption.settings.client_verify_ca_directory = self.verify_ca_directory
        if self.verify_crl_directory:
            encryption.settings.client_verify_crl_directory = self.verify_crl_directory

        if self.trusted_certs_directory:
            encryption.settings.client_trusted_certs_directory = self.trusted_certs_directory
        else:
            encryption.settings.client_trusted_certs_directory = ''

        if self.ca_hint_directory:
            encryption.settings.client_ca_hint_directory = self.ca_hint_directory
        else:
            encryption.settings.client_ca_hint_directory = ''

class ServerCertificateVerifier(AbstractVerifier):
    """
    <class type="servercertificateverifier">
      <summary>
        Class that can be used to verify the certificate of the server-side connection.
      </summary>
      <description>
        <para>This class includes the settings and options used to verify the certificates of the peers in server-side SSL and TLS connections.
        Note that the ServerCertificateVerifier class always requests a certificate from the server.</para>
      </description>
      <metainfo>
        <attributes>
            <attribute state="stable">
                <name>trusted_certs_directory</name>
                <type>
                  <string/>
                </type>
                <default>""</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  A directory where trusted IP address - certificate assignments are
                  stored. When a peer from a specific IP address shows the
                  certificate stored in this directory, it is accepted regardless of
                  its expiration or issuer CA. Each file in the directory should
                  contain a certificate in PEM format. The filename must bethe IP
                  address.
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>trusted</name>
                <default>TRUE</default>
                <type>
                  <boolean/>
                </type>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  If the peer shows a certificate and the <parameter>trusted</parameter> parameter is TRUE, only certificates signed by a trusted CA are accepted.
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>verify_depth</name>
                <type>
                  <integer/>
                </type>
                <default>4</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  The length of the longest accepted CA verification chain. Zorp will automatically reject longer CA chains.
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>verify_ca_directory</name>
                <type>
                  <string/>
                </type>
                <default>""</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Directory where the trusted CA certificates are stored. CA certificates are loaded
                  on-demand from this directory when Zorp verifies the certificate of the peer.
                  <para>Available only in Zorp version 3.4.3 and later.</para>
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>verify_crl_directory</name>
                <type>
                  <string/>
                </type>
                <default>""</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Directory where the CRLs (Certificate Revocation Lists) associated with trusted CAs are stored. CRLs are loaded
                  on-demand from this directory when Zorp verifies the certificate of the peer.
                  <para>Available only in Zorp version 3.4.3 and later.</para>
                </description>
            </attribute>
            <attribute>
                <name>permit_invalid_certificates</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  When <parameter>permit_invalid_certificates</parameter> is TRUE and <parameter>trusted</parameter> is FALSE, Zorp accepts even invalid certificates, for example, expired or self-signed certificates.
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>permit_missing_crl</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  This option has effect only if the <parameter>verify_crl_directory</parameter> parameter is set. If Zorp does not find a CRL in these directories that matches the CAs in the certificate chain and <parameter>permit_missing_crl</parameter> is set to FALSE, Zorp rejects the certificate. Otherwise, the certificate is accepted even if no matching CRL is found.
                  <para>Available only in Zorp version 3.4.3 and later.</para>
                </description>
            </attribute>
            <attribute maturity="stable">
                <name>check_subject</name>
                <type>
                  <boolean/>
                </type>
                <default>TRUE</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  If the <parameter>check_subject</parameter> parameter is TRUE,
                  Zorp compares the Subject of the server-side certificate
                  with application-layer information (for example, it checks
                  whether the Subject matches the hostname in the URL).
                  For details, see <xref linkend="certificate_verification"/>.
                </description>
              </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    def __init__(self, trusted_certs_directory=None, trusted=True, verify_depth=4, verify_ca_directory=None, verify_crl_directory=None, permit_invalid_certificates=False, permit_missing_crl=False, check_subject=True):
        """
        <method maturity="stable">
          <summary>
            Constructor to initialize a ServerCertificateVerifier instance.
          </summary>
          <description>
            <para>
              This constructor defines a ServerCertificateVerifier with the specified parameters.
            </para>
          </description>
          <metainfo>
            <arguments>
                <argument state="stable">
                    <name>trusted_certs_directory</name>
                    <type>
                      <string/>
                    </type>
                    <default>""</default>
                    <description>
                      A directory where trusted IP address - certificate assignments are
                      stored. When a peer from a specific IP address shows the
                      certificate stored in this directory, it is accepted regardless of
                      its expiration or issuer CA. Each file in the directory should
                      contain a certificate in PEM format. The filename must bethe IP
                      address.
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>trusted</name>
                    <default>TRUE</default>
                    <type>
                      <boolean/>
                    </type>
                    <description>
                      If the peer shows a certificate and the <parameter>trusted</parameter> parameter is TRUE, only certificates signed by a trusted CA are accepted.
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>verify_depth</name>
                    <type>
                      <integer/>
                    </type>
                    <default>4</default>
                    <description>
                      The length of the longest accepted CA verification chain. Zorp will automatically reject longer CA chains.
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>verify_ca_directory</name>
                    <type>
                      <string/>
                    </type>
                    <default>""</default>
                    <description>
                      Directory where the trusted CA certificates are stored. CA certificates are loaded
                      on-demand from this directory when Zorp verifies the certificate of the peer.
                      <para>Available only in Zorp version 3.4.3 and later.</para>
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>verify_crl_directory</name>
                    <type>
                      <string/>
                    </type>
                    <default>""</default>
                    <description>
                      Directory where the CRLs (Certificate Revocation Lists) associated with trusted CAs are stored. CRLs are loaded
                      on-demand from this directory when Zorp verifies the certificate of the peer.
                      <para>Available only in Zorp version 3.4.3 and later.</para>
                    </description>
                </argument>
                <argument>
                    <name>permit_invalid_certificates</name>
                    <type>
                      <boolean/>
                    </type>
                    <default>FALSE</default>
                    <description>
                      When <parameter>permit_invalid_certificates</parameter> is TRUE and <parameter>trusted</parameter> is FALSE, Zorp accepts even invalid certificates, for example, expired or self-signed certificates.
                    </description>
                </argument>
                <argument maturity="stable">
                    <name>permit_missing_crl</name>
                    <type>
                      <boolean/>
                    </type>
                    <default>FALSE</default>
                    <description>
                      This option has effect only if the <parameter>verify_crl_directory</parameter> parameter is set. If Zorp does not find a CRL in these directories that matches the CAs in the certificate chain and <parameter>permit_missing_crl</parameter> is set to FALSE, Zorp rejects the certificate. Otherwise, the certificate is accepted even if no matching CRL is found.
                      <para>Available only in Zorp version 3.4.3 and later.</para>
                    </description>
                </argument>
                <argument>
                    <name>check_subject</name>
                    <type>
                      <boolean/>
                    </type>
                    <default>TRUE</default>
                    <conftime>
                      <read/>
                      <write/>
                    </conftime>
                    <runtime>
                      <read/>
                    </runtime>
                    <description>
                      If the <parameter>check_subject</parameter> parameter is TRUE,
                      Zorp compares the Subject of the server-side certificate
                      with application-layer information (for example, it checks
                      whether the Subject matches the hostname in the URL).
                      For details, see <xref linkend="certificate_verification"/>.
                    </description>
                </argument>
            </arguments>
          </metainfo>
        </method>
        """

        super(ServerCertificateVerifier, self).__init__(trusted_certs_directory, True, trusted, verify_depth, verify_ca_directory, verify_crl_directory, permit_invalid_certificates, permit_missing_crl)
        self.check_subject=check_subject

    def setup(self, encryption):
        """
        <method internal="yes"/>
        """
        super(ServerCertificateVerifier, self).setup(encryption)

        encryption.settings.server_verify_type = self.setup_verify_type()

        encryption.settings.server_max_verify_depth = self.verify_depth
        encryption.settings.server_permit_invalid_certificates = self.permit_invalid_certificates
        encryption.settings.server_permit_missing_crl = self.permit_missing_crl

        if self.verify_ca_directory:
            encryption.settings.server_verify_ca_directory = self.verify_ca_directory
        if self.verify_crl_directory:
            encryption.settings.server_verify_crl_directory = self.verify_crl_directory

        if self.trusted_certs_directory:
            encryption.settings.server_trusted_certs_directory = self.trusted_certs_directory
        else:
            encryption.settings.server_trusted_certs_directory = ''

        encryption.settings.server_check_subject = self.check_subject

class ClientNoneVerifier(AbstractVerifier):
    """<class type="clientcertificateverifier">
      <summary>
        Disables certificate verification in client-side connection.
      </summary>
      <description>
        <para>This class disables every certificate verification in client-side SSL and TLS connections.
        </para>
      </description>
      <metainfo>
        <attributes/>
      </metainfo>
      </class>
    """
    def __init__(self):
        """
        <method internal="yes"/>
        """
        pass

    def setup(self, encryption):
            """
            <method internal="yes"/>
            """
            encryption.settings.client_verify_type = SSL_VERIFY_NONE
            encryption.settings.client_trusted_certs_directory = ''

class ServerNoneVerifier(AbstractVerifier):
    """<class type="servercertificateverifier">
      <summary>
        Disables certificate verification in server-side connection.
      </summary>
      <description>
        <para>This class disables every certificate verification in server-side SSL and TLS connections.
        </para>
      </description>
      <metainfo>
        <attributes/>
      </metainfo>
      </class>
    """
    def __init__(self):
        """
        <method internal="yes"/>
        """
        pass

    def setup(self, encryption):
            """
            <method internal="yes"/>
            """
            encryption.settings.server_verify_type = SSL_VERIFY_NONE
            encryption.settings.server_check_subject = FALSE
            encryption.settings.server_trusted_certs_directory = ''

class PrivateKey(object):
    """
    <class type="certprivatekey">
      <summary>
        Class encapsulating a private key.
      </summary>
      <description>
        <para>The PrivateKey class stores a private key and optionally a passphrase for the private key. The private key must be in PEM format.</para>
        <para>When configuring Zorp manually using its configuration file, use the regular constructor of the PrivateKey class to load a private key from a string. To load a private key from a file, use the <link linkend="python.Encryption.PrivateKey.fromFile">PrivateKey.fromFile</link> method.</para>
        <example>
            <title>Loading a private key</title>
            <para>The following example loads a private key from the Zorp configuration file.</para>
            <synopsis>my_private_key = "-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEA9rbxqq+Zi70nRFAZe7SCTB6VgzP1PhkiUm0PmbwFmROSlSSy
yMPSyIzaQqwELyOSQTZtsT3jhd6MCFPBZntym63/GwDuethGSjE9y8rt/9yr+T3I
zz+6ABnZXHJ38tdGYataF1Ndi3CsY5NXGszVFv1Is17P5mbYWQgJ7QzI/a5mPKa+
9pVXsDQthEV3BVUawIEJJnS0THD5XZQJ/MX6F4RPn+2MC9i/RbcA0RVnLPmt2eiy
NV3+55sKdd7GpdMmEbRv9HZyW2xJNyu1xYbwU9YIP88dHCgvqoOgkAX2HLxCJOy6
2gvsS8J7HEbohD98dxPJX7P8w9juORi6Hpsq0wIDAQABAoIBAQDXStIdJtuRC+GG
RXfXca/6iP3j3qV2KSzATRe+CkvAR0o1CC9T7z6zb+bPI5kLIblxWvPiJaW0nn4I
jj5JFhTvMalagTeaz7yW5d2NR2rlSkZwW7Au2uePSv9ZIzL1IVLzzDnz/PW2xv5I
br0mT/Tr+N9GV8iIwNqu5sryp6OFasKB/55LhCcKVYrkdy2WhJc8Y8TXUjF4n8Jn
Xuyd44N6uu5RUiEgN7bPszO1F1T8ujCICwDNnYUw9lwSVvEC2EbTg84lu2UcnE4k
grB7rCKLooDpYlKjXx/1o9Dj9Uv3hwLpSTw2dYRoZS0kOFIKYACP1QcininrTGeL
cOPXyK6BAoGBAPvnBd7/U94Krp9Bp3jjxUEnlFrgf+B7QgRKpG7tN3RDRJmIVL8Z
mnxvbW6o4hsq4TzF/ratnRjqp+79Tw5wUz36G98ftWlTUs62OBznIkwImDGo+ysv
3QK8XUZ4Wg3EcnE5bG8AmOKoDRazc0g7UxopbHC+SNLRMZA/2dBvVh4zAoGBAPq6
UWIfcSnLyFYy7EPh3P7qmotBNPORgcX6aKdwR7pzk6MqTADHxKvIP+eeDEWpF58T
RYBW7KxN4h6cNMglRZBbhED3hONJkpYMGSq0hyczN40SIHHrf3iBO7p35v7Eee82
2H/rT6BNrQF1fPIbz5spgT+eV5BuTAB7bsbWiuDhAoGBALVAgeT26y21mfhVkV9W
5LQA+qp5JworJlFYNADtBx3M2StwASqQDazDsIYTVr4dmHvWK3Teb09iaPt5oMzO
3daWhD+D3VCv98FtM+r4FKGI/Zmd8Twd8HTrfGIcbw/A7mex3efxEhDkwqY28Rhk
N2N3suNcx6GJjJQynVNxCRIpAoGBAOJyIEqUxynOiPOBLm3osiXxUP7wN5i8FA7w
qFCBUecNt4uoCdiyk+fqBf10evT3UQQ07ZKJ71t3RAANaIZTU06buQjMBFMbAa9O
4fP19BLtaQCaHH+HCCuX3I/+9rumS9JHIKX3qoTHYrdsmxo3D/u9MqR4p/EkDLRq
xpQC9I9BAoGBAPZtxtEKc0xhYeuor4qIQbt1edrO+cfEzaXyUvjleLdg8rU3Yeh3
JLbYgcSNr4rMvEwhuvwbwgWJjed7TvqjKKEYYSWW2ESwcmAjNIhDBVzX9oh1cY34
Ae/P63OHt89sWbb5oG2+fcb7xCwH3kYmVgT4/xPv0FQRspwpErKYlCWg
-----END RSA PRIVATE KEY-----"
                    my_private_key_object = PrivateKey(my_private_key, 'mypassphrase')</synopsis>
            <para>The following example loads a private key from an external file.</para>
            <synopsis>my_private_key_object = PrivateKey.fromFile("/tmp/my_private.key", 'mypassphrase')</synopsis>
        </example>
      </description>
      <metainfo>
        <attributes>
          <attribute>
            <name>key_file_path</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
             The path and filename to the private key file. The private key must be in PEM format.
            </description>
          </attribute>
          <attribute>
            <name>passphrase</name>
            <type><string/></type>
            <default>None</default>
            <conftime/>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Passphrase used to access the private key specified in <parameter>key_file_path</parameter>.
            </description>
          </attribute>
         </attributes>
      </metainfo>
    </class>
    """
    def __init__(self, key, passphrase = ""):
        """
        <method maturity="stable">
          <summary>
            Load a private key from a string, and access it using its passphrase
          </summary>
          <description>
            <para>Initializes a PrivateKey instance by loading a private key from a string, and accesses it using its passphrase. To load a private key from a file, use the <link linkend="python.Encryption.PrivateKey.fromFile">PrivateKey.fromFile</link> method.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument>
                <name>key_file_path</name>
                <type>
                    <certificate cert="no" key="yes"/>
                </type>
                <description>
                The path and filename to the private key file. The private key must be in PEM format.
                </description>
              </argument>
              <argument>
                <name>passphrase</name>
                <type><string/></type>
                <default>None</default>
                <conftime/>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  Passphrase used to access the private key specified in <parameter>key_file_path</parameter>.
                </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        self.key = key
        self.passphrase = passphrase

    def getKey(self):
        """
        <method internal="yes"/>
        """
        return self.key

    def getPassPhrase(self):
        """
        <method internal="yes"/>
        """
        return self.passphrase

    @staticmethod
    def fromFile(key_file_path, passphrase = ""):
        """
        <method maturity="stable">
          <summary>
            Load a private key from a file, and access it using its passphrase
          </summary>
          <description>
            <para>Initializes a PrivateKey instance by loading a private key from a file, and accesses it using its passphrase.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument>
                <name>key_file_path</name>
                <type>
                    <certificate cert="no" key="yes"/>
                </type>
                <description>
                The path and filename to the private key file. The private key must be in PEM format.
                </description>
              </argument>
              <argument>
                <name>passphrase</name>
                <type><string/></type>
                <default>None</default>
                <conftime/>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  Passphrase used to access the private key specified in <parameter>key_file_path</parameter>.
                </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        return PrivateKey(readPEM(key_file_path), passphrase)


class DHParam(object):
    """
    <class type="dhparam">
      <summary>
        Class encapsulating DH parameters.
      </summary>
      <description>
        <para>The DHParam class stores DH parameters. The DH parameters must be in PEM format.</para>
        <para>When configuring Zorp manually using its configuration file, use the regular constructor of the DHParam class to load DH parameters key from a string. To load DH parameters key from a file, use the <link linkend="python.Encryption.DHParam.fromFile">DHParam.fromFile</link> method.</para>
        <example>
            <title>Loading DH parameters</title>
            <para>The following example loads DH parameters from the Zorp configuration file.</para>
            <synopsis>my_dh_params = "-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEAvvO8WguTNtkDs33qe5u1T7IjllmTrRnwFV4z7W4A0Du9j+prdRdD
UAblHYBrQn30Fsfg/6WDVTmUj8Lvgn9aFjWYTe6U3Ey7CQt4MBw2BhCO3Rl9KDw7
Im8UdBBhxuekuqZGifMkEEFzAcbiQepvBXiGMucDWgbLaaTY/FrKqb5O9DvoenSV
Aj/VNFnsefQTHXGo1Urg8ixaWj7kTNhM3x7kj7BhK4ALfBuv/93aet2SQjU207C6
0j3mku8CD93Xsbng6rIzmRd6pCANEFH0Rgo1OX7+vMwwG5h5YDsF8cVAcRroZkxR
dyPdVNzYlz1X3Jxln3It/6F2yyx/FOXAGwIBAg==
-----END DH PARAMETERS-----"
                    my_dh_params_object = DHParam(my_dh_params)</synopsis>
            <para>The following example loads DH parameters key from an external file.</para>
            <synopsis>my_dh_params_object = DHParam.fromFile("/tmp/my_dh_params.pem")</synopsis>
        </example>
      </description>
      <metainfo>
        <attributes>
          <attribute>
            <name>params</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
             The path and filename to the DH parameters file. The DH parameters must be in PEM format.
            </description>
          </attribute>
         </attributes>
      </metainfo>
    </class>
    """
    def __init__(self, params):
        """
        <method maturity="stable">
          <summary>
            Load DH parameters key from a string
          </summary>
          <description>
            <para>Initializes a DHParam instance by loading DH parameters key from a string. To load a DH parameters from a file, use the <link linkend="python.Encryption.DHParam.fromFile">DHParam.fromFile</link> method.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument>
                <name>params</name>
                <type>
                    <certificate cert="no" key="yes"/>
                </type>
                <description>
                The path and filename to the DH parameters file. The DH parameters must be in PEM format.
                </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        self.params = params

    def getParams(self):
        """
        <method internal="yes"/>
        """
        return self.params

    @staticmethod
    def fromFile(file_path):
        """
        <method maturity="stable">
          <summary>
            Load a DH parameters from a file
          </summary>
          <description>
            <para>Initializes a DHParam instance by loading a DH parameters from a file.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument>
                <name>file_path</name>
                <type>
                    <dhparam/>
                </type>
                <description>
                The path and filename to the DH parameters file. The DH parameters must be in PEM format.
                </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        return DHParam(readPEM(file_path))

class Certificate(object):
    """
    <class type="certcertificate">
      <summary>
        Class encapsulating a certificate and its private key, and optionally the passphrase for the private key.
      </summary>
      <description>
       <para>The Certificate class stores a certificate, its private key, and optionally a passphrase for the private key. The certificate must be in PEM format.</para>
       <para>When configuring Zorp manually using its configuration file, use the regular constructor of the Certificate class to load a certificate from a string. To load a certificate from a file, use the <link linkend="python.Encryption.Certificate.fromFile">Certificate.fromFile</link> method.</para>
       <example>
            <title>Loading a certificate</title>
            <para>The following example loads a certificate from the Zorp configuration file.</para>
            <synopsis>my_certificate = "-----BEGIN CERTIFICATE-----
MIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL
MAkGA1UECBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMC
VU4xFDASBgNVBAMTC0hlcm9uZyBZYW5nMB4XDTA1MDcxNTIxMTk0N1oXDTA1MDgx
NDIxMTk0N1owVzELMAkGA1UEBhMCQ04xCzAJBgNVBAgTAlBOMQswCQYDVQQHEwJD
TjELMAkGA1UEChMCT04xCzAJBgNVBAsTAlVOMRQwEgYDVQQDEwtIZXJvbmcgWWFu
ZzBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCp5hnG7ogBhtlynpOS21cBewKE/B7j
V14qeyslnr26xZUsSVko36ZnhiaO/zbMOoRcKK9vEcgMtcLFuQTWDl3RAgMBAAGj
gbEwga4wHQYDVR0OBBYEFFXI70krXeQDxZgbaCQoR4jUDncEMH8GA1UdIwR4MHaA
FFXI70krXeQDxZgbaCQoR4jUDncEoVukWTBXMQswCQYDVQQGEwJDTjELMAkGA1UE
CBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMCVU4xFDAS
BgNVBAMTC0hlcm9uZyBZYW5nggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEE
BQADQQA/ugzBrjjK9jcWnDVfGHlk3icNRq0oV7Ri32z/+HQX67aRfgZu7KWdI+Ju
Wm7DCfrPNGVwFWUQOmsPue9rZBgO
-----END CERTIFICATE-----"
                    my_certificate_object = Certificate(my_certificate, 'mypassphrase')</synopsis>
            <para>The following example loads a certificate from an external file.</para>
            <synopsis>my_certificate_object = Certificate.fromFile("/tmp/my_certificate.pem", 'mypassphrase')</synopsis>
        </example>
      </description>
       <metainfo>
        <attributes>
          <attribute>
            <name>certificate_file_path</name>
            <type>
                <certificatechain cert="yes" key="yes"/>
            </type>
            <description>
            The path and filename to the certificate file. The certificate must be in PEM format.
            </description>
          </attribute>
          <attribute>
            <name>private_key_password</name>
            <type><string/></type>
            <default>None</default>
            <description>
              Passphrase used to access the private key of the certificate specified in <parameter>certificate_file_path</parameter>.
            </description>
          </attribute>
        </attributes>
       </metainfo>
    </class>
    """
    def __init__(self, certificate, private_key):
        """
        <method maturity="stable">
          <summary>
            Load a certificate from a string, and access it using its passphrase
          </summary>
          <description>
            <para>Initializes a Certificate instance by loading a certificate from a string, and accesses it using its passphrase. To load a certificate from a file, use the <link linkend="python.Encryption.Certificate.fromFile">Certificate.fromFile</link> method.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument>
                <name>certificate_file_path</name>
                <type>
                    <certificate cert="yes" key="yes" chain="yes"/>
                </type>
                <description>
                The path and filename to the certificate file. The certificate must be in PEM format.
                </description>
              </argument>
              <argument>
                <name>private_key_password</name>
                <type><string/></type>
                <default>None</default>
                <description>
                  Passphrase used to access the private key of the certificate specified in <parameter>certificate_file_path</parameter>.
                </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """

        self.certificate = certificate
        self.private_key = private_key

    def getCertificate(self):
        """
        <method internal="yes"/>
        """
        return self.certificate

    def getPrivateKey(self):
        """
        <method internal="yes"/>
        """
        return self.private_key.getKey()

    def getPassPhrase(self):
        """
        <method internal="yes"/>
        """
        return self.private_key.getPassPhrase()

    @staticmethod
    def fromFile(certificate_file_path, private_key):
        """
        <method maturity="stable">
          <summary>
            Load a certificate from a file, and access it using its passphrase
          </summary>
          <description>
            <para>Initializes a Certificate instance by loading a certificate from a file, and accesses it using its passphrase.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument>
                <name>certificate_file_path</name>
                <type>
                    <certificate cert="yes" key="yes"/>
                </type>
                <description>
                The path and filename to the certificate file. The certificate must be in PEM format.
                </description>
              </argument>
              <argument>
                <name>passphrase</name>
                <type><string/></type>
                <default>None</default>
                <conftime/>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  Passphrase used to access the private key specified in <parameter>certificate_file_path</parameter>.
                </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        return Certificate(readPEM(certificate_file_path), private_key)

class CertificateCA(Certificate):
    """
    <class type="certcertificateca">
     <summary>
        Class encapsulating the certificate of a Certificate Authority (CA certificate) and its private key, and optionally the passphrase for the private key.
      </summary>
      <description>
        <para>The CertificateCA class stores a CA certificate, its private key, and optionally a passphrase for the private key. The certificate must be in PEM format.</para>
      </description>
      <metainfo>
        <attributes>
          <attribute>
            <name>certificate_file_path</name>
            <type>
                <certificate cert="yes" key="yes"/>
            </type>
            <description>
            The path and filename to the certificate file. The certificate must be in PEM format.
            </description>
          </attribute>
          <attribute>
            <name>private_key_password</name>
            <type><string/></type>
            <default>None</default>
            <description>
              Passphrase used to access the private key of the certificate specified in <parameter>certificate_file_path</parameter>.
            </description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    def __init__(self, certificate, private_key):
        """
        <method maturity="stable">
          <summary>
          Load a CAcertificate from a string, and access it using its passphrase
          </summary>
          <description>
            <para>Initializes a CertificateCA instance by loading a CA certificate, and accesses it using its passphrase.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument>
                <name>certificate_file_path</name>
                <type>
                    <certificate cert="yes" key="yes" ca="yes"/>
                </type>
                <description>
                  The path and filename to the CA certificate file. The certificate must be in PEM format.
                </description>
              </argument>
              <argument>
                <name>private_key_password</name>
                <type><string/></type>
                <default>None</default>
                <description>
                  Passphrase used to access the private key specified in <parameter>certificate_file_path</parameter>.
                </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        super(CertificateCA, self).__init__(certificate, private_key)

class AbstractCertificateGenerator(object):
    """
    <class internal="yes" abstract="yes">
      <summary>
        Class encapsulating the abstract Certificate generator.
      </summary>
      <description>
      </description>
      <metainfo>
        <attributes/>
      </metainfo>
    </class>
    """

    def setup(self, encryption):
        """
        <method internal="yes"/>
        """
        raise NotImplementedError

class StaticCertificate(AbstractCertificateGenerator):
    """
    <class type="certificategenerator">
      <summary>
        Class encapsulating a static Certificate object.
      </summary>
      <description>
        This class encapsulates a static Certificate that can be used in SSL/TLS connections.
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>certificate</name>
            <type>
              <class filter="certcertificate" instance="yes"/>
            </type>
            <description>The certificate instance to show to the peer.</description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    def __init__(self, certificate):
        """
        <method maturity="stable">
          <summary>
            Initializes a static Certificate object.
          </summary>
          <description>
            <para>
              A static Certificate that can be used in SSL/TLS connections.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>certificate</name>
                <type>
                  <class filter="certcertificate" instance="yes"/>
                </type>
                <description>The certificate instance to show to the peer.</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        self.certificate = certificate

class ClientStaticCertificate(AbstractCertificateGenerator):
    """
    <class internal="yes">
      <summary/>
      <description/>
      <metainfo>
        <attributes/>
      </metainfo>
    </class>
    """
    def __init__(self, certificate):
        """<method internal="yes">
        </method>
        """
        self.certificate = certificate
    def setup(self, encryption):
        """<method internal="yes">
        </method>
        """
        encryption.settings.client_handshake["setup_key"] = (SSL_HS_POLICY, self.generateCertificate)

    def generateCertificate(self, side, peer_cert, tlsext_server_name, proxy):
        """<method internal="yes">
        </method>
        """
        if self.certificate.getPassPhrase():
            proxy.tls.client_local_privatekey_passphrase = self.certificate.getPassPhrase()

        proxy.tls.client_local_certificate = self.certificate.getCertificate()
        proxy.tls.client_local_privatekey = self.certificate.getPrivateKey()

        return SSL_HS_ACCEPT

class ServerStaticCertificate(AbstractCertificateGenerator):
    """
    <class internal="yes">
      <summary/>
      <description/>
      <metainfo>
        <attributes/>
      </metainfo>
    </class>
    """
    def __init__(self, certificate):
        """<method internal="yes">
        </method>
        """
        self.certificate = certificate
    def setup(self, encryption):
        """<method internal="yes">
        </method>
        """
        encryption.settings.server_handshake["setup_key"] = (SSL_HS_POLICY, self.generateCertificate)

    def generateCertificate(self, side, peer_cert, tlsext_server_name, proxy):
        if self.certificate.getPassPhrase():
            proxy.tls.server_local_privatekey_passphrase = self.certificate.getPassPhrase()

        proxy.tls.server_local_certificate = self.certificate.getCertificate()
        proxy.tls.server_local_privatekey = self.certificate.getPrivateKey()

        return SSL_HS_ACCEPT

class DynamicCertificate(AbstractCertificateGenerator):
    """
    <class type="certificategenerator">
    <summary>
      Class to perform SSL keybridging.
    </summary>
    <description>
      <para>
        This class is able to generate certificates mimicking another
        certificate, primarily used to transfer the information of a server's certificate to the client in keybridging. Can be used only in <link linkend="python.Encryption.TwoSidedEncryption">TwoSidedEncryption</link>. For details on configuring keybridging, see <xref linkend="keybridging"/>.
      </para>
    </description>
    <metainfo>
        <attributes/>
    </metainfo>
    </class>
    """
    def __init__(self, private_key, trusted_ca, untrusted_ca, cache_directory=None, extension_whitelist=None):
        """
        <method maturity="stable">
          <summary>
            Initializes a DynamicCertificate instance to use for keybridging
          </summary>
          <description>
            <para>
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>private_key</name>
                <type>
                  <class filter="certprivatekey" instance="yes"/>
                </type>
                <description>The private key of the CA certificate set in <parameter>trusted_ca</parameter></description>
              </argument>
              <argument maturity="stable">
                <name>trusted_ca</name>
                <type>
                  <class filter="certcertificateca" instance="yes"/>
                </type>
                <description>The CA certificate that Zorp will use to sign the keybridged certificate of trusted peers.</description>
              </argument>
              <argument maturity="stable">
                <name>untrusted_ca</name>
                <type>
                  <class filter="certcertificateca" instance="yes"/>
                </type>
                <description>The CA certificate that Zorp will use to sign the keybridged certificate of untrusted peers.</description>
              </argument>
              <argument maturity="stable">
                <name>cache_directory</name>
                <type>
                  <string/>
                </type>
                <default>None</default>
                <description>The cache directory to store the keybridged certificates generated by Zorp, for example, <filename>/var/lib/zorp/sslbridge/</filename>. The <parameter>zorp</parameter> user must have write privileges for this directory.</description>
              </argument>
              <argument maturity="stable">
                <name>extension_whitelist</name>
                <type>
                  <list><string/></list>
                </type>
                <default>None</default>
                <para>Zorp transfers the following certificate extensions to the client side: <parameter>Key Usage</parameter>, <parameter>Subject Alternative Name</parameter>, <parameter>Extended Key Usage</parameter>. Other extensions will be automatically deleted during keybridging. This is needed because some certificate extensions contain references to the Issuer CA, which references become invalid for keybridged certificates. To transfer other extensions, list them in the <parameter>extension_whitelist</parameter> parameter. Note that modifying this parameter replaces the default values, so to extend the list of transferred extensions, include the <parameter>'keyUsage', 'subjectAltName', 'extendedKeyUsage'</parameter> list as well. For example:</para>
                    <synopsis>self.extension_whitelist = ('keyUsage', 'subjectAltName', 'extendedKeyUsage', 'customExtension')</synopsis>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        self.trusted_ca = trusted_ca
        self.untrusted_ca = untrusted_ca
        self.private_key = private_key
        self.cache_directory = cache_directory
        self.extension_whitelist = extension_whitelist

class ClientDynamicCertificate(AbstractCertificateGenerator):
    """
    <class type="certificategenerator" internal="yes">
      <summary/>
      <description/>
      <metainfo>
        <attributes/>
      </metainfo>
    </class>"""
    def __init__(self, private_key, trusted_ca, untrusted_ca, cache_directory=None, extension_whitelist=None):
        """<method internal="yes">
        </method>
        """
        self.trusted_ca = trusted_ca
        self.untrusted_ca = untrusted_ca
        self.private_key = private_key
        self.cache_directory = cache_directory
        self.extension_whitelist = extension_whitelist

    def setup(self, encryption):
        """<method internal="yes">
        </method>
        """
        encryption.settings.handshake_seq=SSL_HSO_SERVER_CLIENT
        encryption.settings.client_keypair_generate=TRUE
        passphrase = self.private_key.getPassPhrase()
        if passphrase is None:
          passphrase = ""
        self.key_generator=X509KeyBridge(key_pem=self.private_key.getKey(),\
             cache_directory=self.cache_directory,\
             key_passphrase=passphrase,\
             trusted_ca_files=(self.trusted_ca.getCertificate(), self.trusted_ca.getPrivateKey(), self.trusted_ca.getPassPhrase()),\
             untrusted_ca_files=(self.untrusted_ca.getCertificate(), self.untrusted_ca.getPrivateKey(), self.untrusted_ca.getPassPhrase()),\
             extension_whitelist=self.extension_whitelist)

        encryption.settings.client_handshake["setup_key"] = (SSL_HS_POLICY, self.generateKeyClient)

    def generateKeyClient(self, side, peer_cert, tlsext_server_name, proxy):
        """<method internal="yes">
        </method>
        """
        # client side, we need to look up the server key
        if not peer_cert:
            log(proxy.session.session_id, SSL_ERROR, 4, "Unable to generate certificate for the client, no server certificate present, using configured certificate;")
            return SSL_HS_ACCEPT

        if hasattr(self, "key_generator"):
            log(proxy.session.session_id, SSL_DEBUG, 4, "Generating key for the client; trusted='%d'", proxy.tls.server_certificate_trusted)
            if proxy.tls.server_certificate_trusted:
                (proxy.tls.client_local_certificate, proxy.tls.client_local_privatekey) = \
                    self.key_generator.getKeypair(proxy.session.session_id, {'bridge-trusted-key': peer_cert.blob})
            else:
                (proxy.tls.client_local_certificate, proxy.tls.client_local_privatekey) = \
                    self.key_generator.getKeypair(proxy.session.session_id, {'bridge-untrusted-key': peer_cert.blob})
            return SSL_HS_ACCEPT
        else:
            log(proxy.session.session_id, SSL_ERROR, 4, "Unable to generate key for the client, no key generator configured;")
            return SSL_HS_REJECT

class ServerDynamicCertificate(AbstractCertificateGenerator):
    """
    <class type="certificategenerator" internal="yes">
      <summary/>
      <description/>
      <metainfo>
        <attributes/>
      </metainfo>
    </class>"""
    def __init__(self, private_key, trusted_ca, untrusted_ca, cache_directory=None, extension_whitelist=None):
        """<method internal="yes">
        </method>
        """
        self.trusted_ca = trusted_ca
        self.untrusted_ca = untrusted_ca
        self.private_key = private_key
        self.cache_directory = cache_directory
        self.extension_whitelist = extension_whitelist

    def setup(self, encryption):
        """<method internal="yes">
        </method>
        """
        encryption.settings.handshake_seq=SSL_HSO_CLIENT_SERVER
        encryption.settings.server_keypair_generate=TRUE
        passphrase = self.private_key.getPassPhrase()
        if passphrase is None:
          passphrase = ""
        self.key_generator=X509KeyBridge(key_pem=self.private_key.getKey(),\
             cache_directory=self.cache_directory,\
             key_passphrase=passphrase,\
             trusted_ca_files=(self.trusted_ca.getCertificate(), self.trusted_ca.getPrivateKey(), self.trusted_ca.getPassPhrase()),\
             untrusted_ca_files=(self.untrusted_ca.getCertificate(), self.untrusted_ca.getPrivateKey(), self.untrusted_ca.getPassPhrase()),\
             extension_whitelist=self.extension_whitelist)

        encryption.settings.server_handshake["setup_key"] = (SSL_HS_POLICY, self.generateKeyServer)

    def generateKeyServer(self, side, peer_cert, tlsext_server_name, proxy):
        """<method internal="yes">
        </method>
        """
        # server side, we need to look up the client key
        if not peer_cert:
            log(proxy.session.session_id, SSL_ERROR, 4, "Unable to generate certificate for the server, no client certificate present, using configured certificate;")
            return SSL_HS_ACCEPT

        if hasattr(self, "key_generator"):
            log(proxy.session.session_id, SSL_DEBUG, 4, "Generating key for the server; trusted='%d'", proxy.tls.client_certificate_trusted)
            if proxy.tls.client_certificate_trusted:
                (proxy.tls.server_local_certificate, proxy.tls.server_local_privatekey) = \
                    self.key_generator.getKeypair(proxy.session.session_id, {'bridge-trusted-key': peer_cert.blob})
            else:
                (proxy.tls.server_local_certificate, proxy.tls.server_local_privatekey) = \
                    self.key_generator.getKeypair(proxy.session.session_id, {'bridge-untrusted-key': peer_cert.blob})
            return SSL_HS_ACCEPT
        else:
            log(proxy.session.session_id, SSL_ERROR, 4, "Unable to generate key for the server, no key generator configured;")
            return SSL_HS_REJECT

class SNIBasedCertificate(AbstractCertificateGenerator):
    """
    <class type="certificategenerator">
      <summary>
        Class to be used for Server Name Indication (SNI)
      </summary>
      <description>
        This class adds support for the Server Name Indication (SNI) TLS extension,
        as described in <link xmlns:ns1="http://www.w3.org/1999/xlink" ns1:href="http://tools.ietf.org/html/rfc6066">RFC 6066</link>.
        It stores a mapping between hostnames and certificates,
        and automatically selects the certificate to show to the peer
        if the peer has sent an SNI request.
      </description>
      <metainfo>
        <attributes>
          <attribute>
            <name>hostname_certificate_map</name>
            <type>
              <hash>
                <key><class filter="matcher" instance="yes"/></key>
                <value><class filter="certcertificate" instance="yes"/></value>
              </hash>
            </type>
            <description>
              A hash containing a matcher-certificate map. Each element of the hash contains a matcher and a certificate:
              if a matcher matches the hostname in the SNI request, Zorp shows the certificate to the peer.
              You can use any matcher policy, though in most cases, RegexpMatcher will be adequate.
              Different elements of the hash can use different types of matchers, for example, RegexpMatcher and RegexpFileMatcher.
              For details on matcher policies, see <xref linkend="python.Matcher"/>.
              For an example on using SNIBasedCertificate, see <olink targetdoc="zorp-tutorial-https" targetptr="configuring-server-name-indication"/>.
              <synopsis>hostname_certificate_map={
                RegexpMatcher(
                    match_list=("myfirstdomain.example.com", )): StaticCertificate(
                        certificate=Certificate.fromFile(
                            certificate_file_path="/etc/key.d/myfirstdomain/cert.pem",
                            private_key=PrivateKey.fromFile(
                                "/etc/key.d/myfirstdomain/key.pem"))),}</synopsis>
            </description>
          </attribute>
          <attribute>
            <name>default</name>
            <type>
              <class filter="certcertificate" instance="yes"/>
            </type>
            <description>
              The certificate to show to the peer if no matching hostname is found in <parameter>hostname_certificate_map</parameter>.
            </description>
            <default>None</default>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    def __init__(self, hostname_certificate_map, default=None):
        """
        <method maturity="stable">
          <summary>
          </summary>
          <description>
            <para>
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument>
                <name>hostname_certificate_map</name>
                <type>
                  <hash>
                    <key><class filter="matcher" instance="yes"/></key>
                    <value><class filter="certcertificate" instance="yes"/></value>
                  </hash>
                </type>
                <description>
                  A matcher-certificate map that describes which certificate will Zorp show to the peer if the matcher part matches the hostname in the SNI request.
                  For details on matcher policies, see <xref linkend="python.Matcher"/>.
                </description>
              </argument>
              <argument>
                <name>default</name>
                <type>
                  <class filter="certcertificate" instance="yes"/>
                </type>
                <description>
                  The certificate to show to the peer if no matching hostname is found in <parameter>hostname_certificate_map</parameter>.
                </description>
                <default>None</default>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        pass

        self.hostname_certificate_map = hostname_certificate_map
        self.default = default
        for v in self.hostname_certificate_map.itervalues():
            if not isinstance(v, StaticCertificate):
                raise ValueError, "hostname_certificate_map must contain Matcher:StaticCertificate pairs"
        if not isinstance(self.default, StaticCertificate) and self.default != None:
            raise ValueError, "default must be StaticCertificate, or None"

        new_map = {}
        for k, v in self.hostname_certificate_map.items():
            new_map[k] = ClientStaticCertificate(v.certificate)

        self.hostname_certificate_map = new_map

        if self.default:
            self.default = ClientStaticCertificate(self.default.certificate)

    def setup(self, encryption):
        """<method internal="yes">
        </method>
        """
        encryption.settings.client_handshake["setup_key"] = (SSL_HS_POLICY, self.generateCertificate)

    def generateCertificate(self, side, peer_cert, tlsext_server_name, proxy):
        """<method internal="yes">
        </method>
        """
        if tlsext_server_name != "":
            for k, v in self.hostname_certificate_map.items():
                if k.checkMatch(tlsext_server_name):
                    return v.generateCertificate(side, peer_cert, tlsext_server_name, proxy)

        if self.default:
            return self.default.generateCertificate(side, peer_cert, tlsext_server_name, proxy)

        log(proxy.session.session_id, SSL_ERROR, 4, "Not generating certificate for the client, no matching matchers and default=None; servername='%s'", tlsext_server_name)
        return SSL_HS_REJECT

class SidedEncryption(Encryption):
    """
    <class internal="yes">
      <summary/>
      <description/>
      <metainfo>
        <attributes/>
      </metainfo>
    </class>
    """
    def __init__(self, client_security, server_security, client_certificate_generator=None, server_certificate_generator=None, client_ssl_options=ClientSSLOptions(), server_ssl_options=ServerSSLOptions(), client_verify=ClientNoneVerifier(), server_verify=ServerNoneVerifier()):
        """<method internal="yes">
        </method>
        """
        super(SidedEncryption, self).__init__(client_security=client_security, server_security=server_security,
                                              client_timeout=client_ssl_options.timeout, server_timeout=server_ssl_options.timeout,
                                             )

        self.settings.client_handshake["verify_cert_ext"] = (SSL_HS_POLICY, SidedEncryption.verifyTrustedCertClient)
        self.settings.server_handshake["verify_cert_ext"] = (SSL_HS_POLICY, SidedEncryption.verifyTrustedCertServer)

        self.settings.client_keypair_generate = FALSE
        self.settings.server_keypair_generate = FALSE

        self.client_verify = client_verify
        if self.client_verify == None:
            self.client_verify = ClientNoneVerifier()

        self.server_verify = server_verify
        if self.server_verify == None:
            self.server_verify = ServerNoneVerifier()

        self.client_ssl_options = client_ssl_options
        self.server_ssl_options = server_ssl_options
        self.client_certificate_generator = client_certificate_generator
        self.server_certificate_generator = server_certificate_generator

        if isinstance(client_certificate_generator, DynamicCertificate):
            self.client_certificate_generator = ClientDynamicCertificate(client_certificate_generator.private_key, client_certificate_generator.trusted_ca, client_certificate_generator.untrusted_ca, client_certificate_generator.cache_directory, client_certificate_generator.extension_whitelist)
        if isinstance(client_certificate_generator, StaticCertificate):
            self.client_certificate_generator = ClientStaticCertificate(client_certificate_generator.certificate)

        if isinstance(server_certificate_generator, DynamicCertificate):
            self.server_certificate_generator = ServerDynamicCertificate(server_certificate_generator.private_key, server_certificate_generator.trusted_ca, server_certificate_generator.untrusted_ca, server_certificate_generator.cache_directory, server_certificate_generator.extension_whitelist)
        if isinstance(server_certificate_generator, StaticCertificate):
            self.server_certificate_generator = ServerStaticCertificate(server_certificate_generator.certificate)

    def setup(self, encryption):
        """<method internal="yes">
        </method>
        """
        if self.client_certificate_generator:
            self.client_certificate_generator.setup(encryption)
        if self.server_certificate_generator:
            self.server_certificate_generator.setup(encryption)

        self.client_verify.setup(encryption)
        self.server_verify.setup(encryption)
        self.client_ssl_options.setup(encryption)
        self.server_ssl_options.setup(encryption)
        if not super(SidedEncryption, self).setup():
            raise Exception, "Encryption.setup() returned error;"

    @staticmethod
    def verifyTrustedCert(side, verify_results, trusted_certs_dir, blob, proxy):
        """<method internal="yes">
        </method>
        """
        if trusted_certs_dir:
            if side == 1:
                f = '%s/%s:%d' % (proxy.encryption.settings.server_trusted_certs_directory, proxy.session.server_address.ip_s, proxy.session.server_address.port)
            elif side == 0:
                f = '%s/%s' % (proxy.encryption.settings.client_trusted_certs_directory, proxy.session.client_address.ip_s)
        else:
            return SSL_HS_ACCEPT

        log(proxy.session.session_id, SSL_DEBUG, 6, "Testing trusted certificates; f='%s'", (f,))
        if blob and os.access(f, os.R_OK):
            if readPEM(f) == blob:
                log(proxy.session.session_id, SSL_INFO, 4, "Trusting peer certificate; stored_cert='%s'", f)
                return SSL_HS_VERIFIED
            else:
                log(proxy.session.session_id, SSL_VIOLATION, 2, "Peer certificate differs from trusted cert; stored_cert='%s'", f)
                return SSL_HS_REJECT

        return SSL_HS_ACCEPT

    @staticmethod
    def verifyTrustedCertServer(side, verify_results, peer_cert, proxy):
        """<method internal="yes">
        </method>"""
        res = SidedEncryption.verifyTrustedCert(side, verify_results, proxy.encryption.settings.server_trusted_certs_directory, peer_cert.blob, proxy)
        if res == SSL_HS_VERIFIED or (res == SSL_HS_ACCEPT and verify_results[0]):
            proxy.tls.server_certificate_trusted = TRUE
        return res

    @staticmethod
    def verifyTrustedCertClient(side, verify_results, peer_cert, proxy):
        """<method internal="yes">
        </method>
        """
        res = SidedEncryption.verifyTrustedCert(side, verify_results, proxy.encryption.settings.client_trusted_certs_directory, peer_cert.blob, proxy)
        if res == SSL_HS_VERIFIED or (res == SSL_HS_ACCEPT and verify_results[0]):
            proxy.tls.client_certificate_trusted = TRUE
        return res

class ClientOnlyStartTLSEncryption(SidedEncryption):
    """
    <class type="encryption">
      <summary>
        The client can optionally request STARTTLS encryption, but the server-side connection is always unencrypted.
      </summary>
      <description>
        The ClientOnlyStartTLSEncryption class handles scenarios when the client can optionally request STARTTLS encryption.
        If the client sends a STARTTLS request, the client-side connection will use STARTTLS.
        The server-side connection will not be encrypted.
        <warning>
            <para>If the client does not send a STARTTLS request, the client-side communication will not be encrypted at all.
            The server-side connection will never be encrypted.
            </para>
        </warning>
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>client_certificate_generator</name>
            <type><class filter="certificategenerator" instance="yes"/></type>
            <description>The class that will generate the certificate Zorp shows to the client. You can use an instance of the <link linkend="python.Encryption.StaticCertificate">StaticCertificate</link>, <link linkend="python.Encryption.DynamicCertificate">DynamicCertificate</link>, or <link linkend="python.Encryption.SNIBasedCertificate">SNIBasedCertificate</link> classes. </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_verify</name>
            <type><class filter="clientcertificateverifier" instance="yes"/></type>
            <default>ClientCertificateVerifierGroup()</default>
            <description>The settings used to verify the certificate of the client. This must be a <link linkend="python.Encryption.ClientCertificateVerifier">ClientCertificateVerifier</link> instance. </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_ssl_options</name>
            <type><class filter="clientssloptions" instance="yes"/></type>
            <default>ClientSSLOptions()</default>
            <description>The protocol-level encryption settings used on the client side. This must be a <link linkend="python.Encryption.ClientSSLOptions">ClientSSLOptions</link> instance. </description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    def __init__(self, client_certificate_generator, client_verify=ClientCertificateVerifier(), client_ssl_options=ClientSSLOptions()):
        """
        <method maturity="stable">
          <summary>
            The client can optionally request STARTTLS encryption, but the server-side connection is always unencrypted.
          </summary>
          <description>
            The ClientOnlyStartTLSEncryption class handles scenarios when the client can optionally request STARTTLS encryption.
            If the client sends a STARTTLS request, the client-side connection will use STARTTLS.
            The server-side connection will not be encrypted.
            <warning>
                <para>If the client does not send a STARTTLS request, the client-side communication will not be encrypted at all.
                The server-side connection will never be encrypted.
                </para>
            </warning>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>client_certificate_generator</name>
                <type><class filter="certificategenerator" instance="yes"/></type>
                <description>The class that will generate the certificate Zorp shows to the client. You can use an instance of the <link linkend="python.Encryption.StaticCertificate">StaticCertificate</link>, <link linkend="python.Encryption.DynamicCertificate">DynamicCertificate</link>, or <link linkend="python.Encryption.SNIBasedCertificate">SNIBasedCertificate</link> classes. </description>
              </argument>
              <argument maturity="stable">
                <name>client_verify</name>
                <type><class filter="clientcertificateverifier" instance="yes"/></type>
                <default>ClientCertificateVerifier()</default>
                <description>The settings used to verify the certificate of the client. This must be a <link linkend="python.Encryption.ClientCertificateVerifier">ClientCertificateVerifier</link> instance. </description>
              </argument>
              <argument maturity="stable">
                <name>client_ssl_options</name>
                <type><class filter="clientssloptions" instance="yes"/></type>
                <default>ClientSSLOptions()</default>
                <description>The protocol-level encryption settings used on the client side. This must be a <link linkend="python.Encryption.ClientSSLOptions">ClientSSLOptions</link> instance. </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        if not isinstance(client_ssl_options, ClientSSLOptions) and client_ssl_options != None:
            raise ValueError, "client_ssl_options must be either ClientSSLOptions, or None"

        super(ClientOnlyStartTLSEncryption, self).__init__(client_security=SSL_ACCEPT_STARTTLS, server_security=SSL_NONE, client_certificate_generator=client_certificate_generator, client_verify=client_verify, client_ssl_options=client_ssl_options)
        super(ClientOnlyStartTLSEncryption, self).setup(self)

class FakeStartTLSEncryption(SidedEncryption):
    """
    <class type="encryption">
      <summary>
        The client can optionally request STARTTLS encryption, but the server-side connection is always encrypted.
      </summary>
      <description>
        The FakeStartTLSEncryption class handles scenarios when the client can optionally request STARTTLS encryption.
        If the client sends a STARTTLS request, the client-side connection will use STARTTLS.
        The server-side connection will always be encrypted.
        <warning>
            <para>If the client does not send a STARTTLS request, the client-side communication will not be encrypted at all.
            The server-side connection will always be encrypted.
            </para>
        </warning>
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>client_certificate_generator</name>
            <type><class filter="certificategenerator" instance="yes"/></type>
            <description>The class that will generate the certificate Zorp shows to the client. You can use an instance of the <link linkend="python.Encryption.StaticCertificate">StaticCertificate</link>, <link linkend="python.Encryption.DynamicCertificate">DynamicCertificate</link>, or <link linkend="python.Encryption.SNIBasedCertificate">SNIBasedCertificate</link> classes. </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_verify</name>
            <type><class filter="clientcertificateverifier" instance="yes"/></type>
            <default>ClientCertificateVerifierGroup()</default>
            <description>The settings used to verify the certificate of the client. This must be a <link linkend="python.Encryption.ClientCertificateVerifier">ClientCertificateVerifier</link> instance. </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_verify</name>
            <type><class filter="servercertificateverifier" instance="yes"/></type>
            <default>ServerCertificateVerifierGroup()</default>
            <description>The settings used to verify the certificate of the server. This must be a <link linkend="python.Encryption.ServerCertificateVerifier">ServerCertificateVerifier</link> instance. </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_ssl_options</name>
            <type><class filter="clientssloptions" instance="yes"/></type>
            <default>ClientSSLOptions()</default>
            <description>The protocol-level encryption settings used on the client side. This must be a <link linkend="python.Encryption.ClientSSLOptions">ClientSSLOptions</link> instance. </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_ssl_options</name>
            <type><class filter="serverssloptions" instance="yes"/></type>
            <default>ServerSSLOptions()</default>
            <description>The protocol-level encryption settings used on the server side. This must be a <link linkend="python.Encryption.ServerSSLOptions">ServerSSLOptions</link> instance. </description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    def __init__(self, client_certificate_generator, client_verify=ClientCertificateVerifier(), server_verify=ServerCertificateVerifier(), client_ssl_options=ClientSSLOptions(), server_ssl_options=ServerSSLOptions()):
        """
        <method maturity="stable">
          <summary>
            Initializes a FakeStartTLSEncryption instance to handle scenarios when the client can optionally request STARTTLS encryption.
          </summary>
          <description>
            The FakeStartTLSEncryption class handles scenarios when the client can optionally request STARTTLS encryption.
            If the client sends a STARTTLS request, the client-side connection will use STARTTLS.
            The server-side connection will always be encrypted.
            <warning>
                <para>If the client does not send a STARTTLS request, the client-side communication will not be encrypted at all.
                The server-side connection will always be encrypted.
                </para>
            </warning>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>client_certificate_generator</name>
                <type><class filter="certificategenerator" instance="yes"/></type>
                <description>The class that will generate the certificate Zorp shows to the client. You can use an instance of the <link linkend="python.Encryption.StaticCertificate">StaticCertificate</link>, <link linkend="python.Encryption.DynamicCertificate">DynamicCertificate</link>, or <link linkend="python.Encryption.SNIBasedCertificate">SNIBasedCertificate</link> classes. </description>
              </argument>
              <argument maturity="stable">
                <name>client_verify</name>
                <type><class filter="clientcertificateverifier" instance="yes"/></type>
                <default>ClientCertificateVerifierGroup()</default>
                <description>The settings used to verify the certificate of the client. This must be a <link linkend="python.Encryption.ClientCertificateVerifier">ClientCertificateVerifier</link> instance. </description>
              </argument>
              <argument maturity="stable">
                <name>server_verify</name>
                <type><class filter="servercertificateverifier" instance="yes"/></type>
                <default>ServerCertificateVerifierGroup()</default>
                <description>The settings used to verify the certificate of the server. This must be a <link linkend="python.Encryption.ServerCertificateVerifier">ServerCertificateVerifier</link> instance. </description>
              </argument>
              <argument maturity="stable">
                <name>client_ssl_options</name>
                <type><class filter="clientssloptions" instance="yes"/></type>
                <default>ClientSSLOptions()</default>
                <description>The protocol-level encryption settings used on the client side. This must be a <link linkend="python.Encryption.ClientSSLOptions">ClientSSLOptions</link> instance. </description>
              </argument>
              <argument maturity="stable">
                <name>server_ssl_options</name>
                <type><class filter="serverssloptions" instance="yes"/></type>
                <default>ServerSSLOptions()</default>
                <description>The protocol-level encryption settings used on the server side. This must be a <link linkend="python.Encryption.ServerSSLOptions">ServerSSLOptions</link> instance. </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        if not isinstance(client_ssl_options, ClientSSLOptions) and client_ssl_options != None:
            raise ValueError, "client_ssl_options must be either ClientSSLOptions, or None"

        if not isinstance(server_ssl_options, ServerSSLOptions) and server_ssl_options != None:
            raise ValueError, "server_ssl_options must be either ServerSSLOptions, or None"

        super(FakeStartTLSEncryption, self).__init__(client_security=SSL_ACCEPT_STARTTLS, server_security=SSL_FORCE_SSL, client_certificate_generator=client_certificate_generator, client_verify=client_verify, server_verify=server_verify, client_ssl_options=client_ssl_options, server_ssl_options=server_ssl_options)
        super(FakeStartTLSEncryption, self).setup(self)

class ForwardStartTLSEncryption(SidedEncryption):
    """
    <class type="encryption">
      <summary>
        The ForwardStartTLSEncryption class handles scenarios when the client can optionally request STARTTLS encryption.
      </summary>
      <description>
        The ForwardStartTLSEncryption class handles scenarios when the client can optionally request STARTTLS encryption.
        If the client sends a STARTTLS request, the client-side connection will use STARTTLS, and Zorp will forward the request to the server.
        If the server supports STARTTLS, the server-side connection will also use STARTTLS.
        <warning>
            <para>If the client does not send a STARTTLS request, the communication will not be encrypted at all. Both the client-Zorp and the Zorp-server connections will be unencrypted.</para>
        </warning>
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>client_certificate_generator</name>
            <type><class filter="certificategenerator" instance="yes"/></type>
            <description>The class that will generate the certificate Zorp shows to the client. You can use an instance of the <link linkend="python.Encryption.StaticCertificate">StaticCertificate</link>, <link linkend="python.Encryption.DynamicCertificate">DynamicCertificate</link>, or <link linkend="python.Encryption.SNIBasedCertificate">SNIBasedCertificate</link> classes. </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_verify</name>
            <type><class filter="clientcertificateverifier" instance="yes"/></type>
            <default>ClientCertificateVerifierGroup()</default>
            <description>The settings used to verify the certificate of the client. This must be a <link linkend="python.Encryption.ClientCertificateVerifier">ClientCertificateVerifier</link> instance. </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_verify</name>
            <type><class filter="servercertificateverifier" instance="yes"/></type>
            <default>ServerCertificateVerifierGroup()</default>
            <description>The settings used to verify the certificate of the server. This must be a <link linkend="python.Encryption.ServerCertificateVerifier">ServerCertificateVerifier</link> instance. </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_ssl_options</name>
            <type><class filter="clientssloptions" instance="yes"/></type>
            <default>ClientSSLOptions()</default>
            <description>The protocol-level encryption settings used on the client side. This must be a <link linkend="python.Encryption.ClientSSLOptions">ClientSSLOptions</link> instance. </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_ssl_options</name>
            <type><class filter="serverssloptions" instance="yes"/></type>
            <default>ServerSSLOptions()</default>
            <description>The protocol-level encryption settings used on the server side. This must be a <link linkend="python.Encryption.ServerSSLOptions">ServerSSLOptions</link> instance. </description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    def __init__(self, client_certificate_generator, client_verify=ClientCertificateVerifier(), server_verify=ServerCertificateVerifier(), client_ssl_options=ClientSSLOptions(), server_ssl_options=ServerSSLOptions()):
        """
        <method maturity="stable">
          <summary>
            Initializes a ForwardStartTLSEncryption instance to handle scenarios when the client can optionally request STARTTLS encryption.
          </summary>
          <description>
            Initializes a ForwardStartTLSEncryption instance to handle scenarios when the client can optionally request STARTTLS encryption.
            If the client sends a STARTTLS request, the client-side connection will use STARTTLS, and Zorp will forward the request to the server.
            If the server supports STARTTLS, the server-side connection will also use STARTTLS.
            <warning>
                <para>If the client does not send a STARTTLS request, the communication will not be encrypted at all. Both the client-Zorp and the Zorp-server connections will be unencrypted.</para>
            </warning>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>client_certificate_generator</name>
                <type><class filter="certificategenerator" instance="yes"/></type>
                <description>The class that will generate the certificate Zorp shows to the client. You can use an instance of the <link linkend="python.Encryption.StaticCertificate">StaticCertificate</link>, <link linkend="python.Encryption.DynamicCertificate">DynamicCertificate</link>, or <link linkend="python.Encryption.SNIBasedCertificate">SNIBasedCertificate</link> classes. </description>
              </argument>
              <argument maturity="stable">
                <name>client_verify</name>
                <type><class filter="clientcertificateverifier" instance="yes"/></type>
                <default>ClientCertificateVerifierGroup()</default>
                <description>The settings used to verify the certificate of the client. This must be a <link linkend="python.Encryption.ClientCertificateVerifier">ClientCertificateVerifier</link> instance. </description>
              </argument>
              <argument maturity="stable">
                <name>server_verify</name>
                <type><class filter="servercertificateverifier" instance="yes"/></type>
                <default>ServerCertificateVerifierGroup()</default>
                <description>The settings used to verify the certificate of the server. This must be a <link linkend="python.Encryption.ServerCertificateVerifier">ServerCertificateVerifier</link> instance. </description>
              </argument>
              <argument maturity="stable">
                <name>client_ssl_options</name>
                <type><class filter="clientssloptions" instance="yes"/></type>
                <default>ClientSSLOptions()</default>
                <description>The protocol-level encryption settings used on the client side. This must be a <link linkend="python.Encryption.ClientSSLOptions">ClientSSLOptions</link> instance. </description>
              </argument>
              <argument maturity="stable">
                <name>server_ssl_options</name>
                <type><class filter="serverssloptions" instance="yes"/></type>
                <default>ServerSSLOptions()</default>
                <description>The protocol-level encryption settings used on the server side. This must be a <link linkend="python.Encryption.ServerSSLOptions">ServerSSLOptions</link> instance. </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """

        if not isinstance(client_ssl_options, ClientSSLOptions) and client_ssl_options != None:
            raise ValueError, "client_ssl_options must be either ClientSSLOptions, or None"

        if not isinstance(server_ssl_options, ServerSSLOptions) and server_ssl_options != None:
            raise ValueError, "server_ssl_options must be either ServerSSLOptions, or None"

        super(ForwardStartTLSEncryption, self).__init__(client_security=SSL_ACCEPT_STARTTLS, server_security=SSL_FORWARD_STARTTLS, client_certificate_generator=client_certificate_generator, client_verify=client_verify, server_verify=server_verify, client_ssl_options=client_ssl_options, server_ssl_options=server_ssl_options)
        super(ForwardStartTLSEncryption, self).setup(self)

class ClientOnlyEncryption(SidedEncryption):
    """
    <class type="encryption">
      <summary>
        The ClientOnlyEncryption class handles scenarios when only the client-Zorp connection is encrypted, the Zorp-server connection is not
      </summary>
      <description>
        The ClientOnlyEncryption class handles scenarios when only the client-Zorp connection is encrypted, the Zorp-server connection is not.
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>client_certificate_generator</name>
            <type><class filter="certificategenerator" instance="yes"/></type>
            <description>The class that will generate the certificate Zorp shows to the client. You can use an instance of the <link linkend="python.Encryption.StaticCertificate">StaticCertificate</link>, <link linkend="python.Encryption.DynamicCertificate">DynamicCertificate</link>, or <link linkend="python.Encryption.SNIBasedCertificate">SNIBasedCertificate</link> classes. </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_verify</name>
            <type><class filter="clientcertificateverifier" instance="yes"/></type>
            <default>ClientCertificateVerifierGroup()</default>
            <description>The settings used to verify the certificate of the client. This must be a <link linkend="python.Encryption.ClientCertificateVerifier">ClientCertificateVerifier</link> instance. </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_ssl_options</name>
            <type><class filter="clientssloptions" instance="yes"/></type>
            <default>ClientSSLOptions()</default>
            <description>The protocol-level encryption settings used on the client side. This must be a <link linkend="python.Encryption.ClientSSLOptions">ClientSSLOptions</link> instance. </description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    def __init__(self, client_certificate_generator, client_verify=ClientCertificateVerifier(), client_ssl_options=ClientSSLOptions()):
        """
        <method maturity="stable">
          <summary>Initializes SSL/TLS connection on the client side.
          </summary>
          <description>
            <para>The ClientOnlyEncryption class handles scenarios when only the client-Zorp connection is encrypted, the Zorp-server connection is not.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>client_certificate_generator</name>
                <type><class filter="certificategenerator" instance="yes"/></type>
                <description>The class that will generate the certificate Zorp shows to the client. You can use an instance of the <link linkend="python.Encryption.StaticCertificate">StaticCertificate</link>, <link linkend="python.Encryption.DynamicCertificate">DynamicCertificate</link>, or <link linkend="python.Encryption.SNIBasedCertificate">SNIBasedCertificate</link> classes. </description>
              </argument>
              <argument maturity="stable">
                <name>client_verify</name>
                <type><class filter="clientcertificateverifier" instance="yes"/></type>
                <default>ClientCertificateVerifierGroup()</default>
                <description>The settings used to verify the certificate of the client. This must be a <link linkend="python.Encryption.ClientCertificateVerifier">ClientCertificateVerifier</link> instance. </description>
              </argument>
              <argument maturity="stable">
                <name>client_ssl_options</name>
                <type><class filter="clientssloptions" instance="yes"/></type>
                <default>ClientSSLOptions()</default>
                <description>The protocol-level encryption settings used on the client side. This must be a <link linkend="python.Encryption.ClientSSLOptions">ClientSSLOptions</link> instance. </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        if not isinstance(client_ssl_options, ClientSSLOptions) and client_ssl_options != None:
            raise ValueError, "client_ssl_options must be either ClientSSLOptions, or None"

        super(ClientOnlyEncryption, self).__init__(client_security=SSL_FORCE_SSL, server_security=SSL_NONE, client_certificate_generator=client_certificate_generator, client_verify=client_verify, client_ssl_options=client_ssl_options)
        super(ClientOnlyEncryption, self).setup(self)

class ServerOnlyEncryption(SidedEncryption):
    """
    <class type="encryption">
      <summary>
        The ServerOnlyEncryption class handles scenarios when only the Zorp-server connection is encrypted, the client-Zorp connection is not
      </summary>
      <description>
        The ServerOnlyEncryption class handles scenarios when only the Zorp-server connection is encrypted, the client-Zorp connection is not.
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>server_certificate_generator</name>
            <type><class filter="certificategenerator" instance="yes"/></type>
            <default>None</default>
            <description>The class that will generate the certificate Zorp shows to the server. You can use an instance of the <link linkend="python.Encryption.StaticCertificate">StaticCertificate</link>, <link linkend="python.Encryption.DynamicCertificate">DynamicCertificate</link>, or <link linkend="python.Encryption.SNIBasedCertificate">SNIBasedCertificate</link> classes. </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_verify</name>
            <type><class filter="servercertificateverifier" instance="yes"/></type>
            <default>ServerCertificateVerifierGroup()</default>
            <description>The settings used to verify the certificate of the server. This must be a <link linkend="python.Encryption.ServerCertificateVerifier">ServerCertificateVerifier</link> instance. </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_ssl_options</name>
            <type><class filter="serverssloptions" instance="yes"/></type>
            <default>ServerSSLOptions()</default>
            <description>The protocol-level encryption settings used on the server side. This must be a <link linkend="python.Encryption.ServerSSLOptions">ServerSSLOptions</link> instance. </description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    def __init__(self, server_certificate_generator=None, server_verify=ServerCertificateVerifier(), server_ssl_options=ServerSSLOptions()):
        """<method maturity="stable">
          <summary>Initializes SSL/TLS connection on the server side.
          </summary>
          <description>
            <para>The ServerOnlyEncryption class handles scenarios when only the Zorp-server connection is encrypted, the client-Zorp connection is not.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>server_certificate_generator</name>
                <type><class filter="certificategenerator" instance="yes"/></type>
                <default>None</default>
                <description>The class that will generate the certificate Zorp shows to the server. You can use an instance of the <link linkend="python.Encryption.StaticCertificate">StaticCertificate</link>, <link linkend="python.Encryption.DynamicCertificate">DynamicCertificate</link>, or <link linkend="python.Encryption.SNIBasedCertificate">SNIBasedCertificate</link> classes. </description>
              </argument>
              <argument maturity="stable">
                <name>server_verify</name>
                <type><class filter="servercertificateverifier" instance="yes"/></type>
                <default>ServerCertificateVerifierGroup()</default>
                <description>The settings used to verify the certificate of the server. This must be a <link linkend="python.Encryption.ServerCertificateVerifier">ServerCertificateVerifier</link> instance. </description>
              </argument>
              <argument maturity="stable">
                <name>server_ssl_options</name>
                <type><class filter="serverssloptions" instance="yes"/></type>
                <default>ServerSSLOptions()</default>
                <description>The protocol-level encryption settings used on the server side. This must be a <link linkend="python.Encryption.ServerSSLOptions">ServerSSLOptions</link> instance. </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        if not isinstance(server_ssl_options, ServerSSLOptions) and server_ssl_options != None:
            raise ValueError, "server_ssl_options must be either ServerSSLOptions, or None"

        if not isinstance(server_verify, ServerCertificateVerifier) and not isinstance(server_verify, ServerNoneVerifier) and server_verify != None:
            raise ValueError, "server_verify must be either ServerCertificateVerifier, ServerNoneVerifier or None"

        if isinstance(server_certificate_generator, SNIBasedCertificate):
            raise ValueError, "server_certificate_generator must be either StaticCertificate, DynamicCertificate or None"

        super(ServerOnlyEncryption, self).__init__(client_security=SSL_NONE, server_security=SSL_FORCE_SSL, server_certificate_generator=server_certificate_generator, server_verify=server_verify, server_ssl_options=server_ssl_options)
        super(ServerOnlyEncryption, self).setup(self)

class TwoSidedEncryption(SidedEncryption):
    """
    <class type="encryption">
      <summary>
        The TwoSidedEncryption class handles scenarios when both the client-Zorp and the Zorp-server connections are encrypted.
      </summary>
      <description>
        The TwoSidedEncryption class handles scenarios when both the client-Zorp and the Zorp-server connections are encrypted.
        If you do not need encryption on the client- or the server-side, use the <link linkend="python.Encryption.ServerOnlyEncryption">ServerOnlyEncryption</link> or <link linkend="python.Encryption.ClientOnlyEncryption">ClientOnlyEncryption</link> classes, respectively.
        For a detailed example on keybridging, see <xref linkend="keybridging"/>.
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>client_certificate_generator</name>
            <type><class filter="certificategenerator" instance="yes"/></type>
            <description>The class that will generate the certificate Zorp shows to the client. You can use an instance of the <link linkend="python.Encryption.StaticCertificate">StaticCertificate</link>, <link linkend="python.Encryption.DynamicCertificate">DynamicCertificate</link>, or <link linkend="python.Encryption.SNIBasedCertificate">SNIBasedCertificate</link> classes. </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_certificate_generator</name>
            <type><class filter="certificategenerator" instance="yes"/></type>
            <default>None</default>
            <description>The class that will generate the certificate Zorp shows to the server. You can use an instance of the <link linkend="python.Encryption.StaticCertificate">StaticCertificate</link>, <link linkend="python.Encryption.DynamicCertificate">DynamicCertificate</link>, or <link linkend="python.Encryption.SNIBasedCertificate">SNIBasedCertificate</link> classes. </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_verify</name>
            <type><class filter="clientcertificateverifier" instance="yes"/></type>
            <default>ClientCertificateVerifierGroup()</default>
            <description>The settings used to verify the certificate of the client. This must be a <link linkend="python.Encryption.ClientCertificateVerifier">ClientCertificateVerifier</link> instance. </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_verify</name>
            <type><class filter="servercertificateverifier" instance="yes"/></type>
            <default>ServerCertificateVerifierGroup()</default>
            <description>The settings used to verify the certificate of the server. This must be a <link linkend="python.Encryption.ServerCertificateVerifier">ServerCertificateVerifier</link> instance. </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_ssl_options</name>
            <type><class filter="clientssloptions" instance="yes"/></type>
            <default>ClientSSLOptions()</default>
            <description>The protocol-level encryption settings used on the client side. This must be a <link linkend="python.Encryption.ClientSSLOptions">ClientSSLOptions</link> instance. </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_ssl_options</name>
            <type><class filter="serverssloptions" instance="yes"/></type>
            <default>ServerSSLOptions()</default>
            <description>The protocol-level encryption settings used on the server side. This must be a <link linkend="python.Encryption.ServerSSLOptions">ServerSSLOptions</link> instance. </description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    def __init__(self, client_certificate_generator, server_certificate_generator=None, client_verify=ClientCertificateVerifier(), server_verify=ServerCertificateVerifier(), client_ssl_options=ClientSSLOptions(), server_ssl_options=ServerSSLOptions()):
        """
        <method maturity="stable">
          <summary>Initializes SSL/TLS connection with both peers.
          </summary>
          <description>
            <para>The TwoSidedEncryption class handles scenarios when both the client-Zorp and the Zorp-server connections are encrypted.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>client_certificate_generator</name>
                <type><class filter="certificategenerator" instance="yes"/></type>
                <description>The class that will generate the certificate Zorp shows to the client. You can use an instance of the <link linkend="python.Encryption.StaticCertificate">StaticCertificate</link>, <link linkend="python.Encryption.DynamicCertificate">DynamicCertificate</link>, or <link linkend="python.Encryption.SNIBasedCertificate">SNIBasedCertificate</link> classes. </description>
              </argument>
              <argument maturity="stable">
                <name>server_certificate_generator</name>
                <type><class filter="certificategenerator" instance="yes"/></type>
                <default>None</default>
                <description>The class that will generate the certificate Zorp shows to the server. You can use an instance of the <link linkend="python.Encryption.StaticCertificate">StaticCertificate</link>, <link linkend="python.Encryption.DynamicCertificate">DynamicCertificate</link>, or <link linkend="python.Encryption.SNIBasedCertificate">SNIBasedCertificate</link> classes. </description>
              </argument>
              <argument maturity="stable">
                <name>client_verify</name>
                <type><class filter="clientcertificateverifier" instance="yes"/></type>
                <default>ClientCertificateVerifierGroup()</default>
                <description>The settings used to verify the certificate of the client. This must be a <link linkend="python.Encryption.ClientCertificateVerifier">ClientCertificateVerifier</link> instance. </description>
              </argument>
              <argument maturity="stable">
                <name>server_verify</name>
                <type><class filter="servercertificateverifier" instance="yes"/></type>
                <default>ServerCertificateVerifierGroup()</default>
                <description>The settings used to verify the certificate of the server. This must be a <link linkend="python.Encryption.ServerCertificateVerifier">ServerCertificateVerifier</link> instance. </description>
              </argument>
              <argument maturity="stable">
                <name>client_ssl_options</name>
                <type><class filter="clientssloptions" instance="yes"/></type>
                <default>ClientSSLOptions()</default>
                <description>The protocol-level encryption settings used on the client side. This must be a <link linkend="python.Encryption.ClientSSLOptions">ClientSSLOptions</link> instance. </description>
              </argument>
              <argument maturity="stable">
                <name>server_ssl_options</name>
                <type><class filter="serverssloptions" instance="yes"/></type>
                <default>ServerSSLOptions()</default>
                <description>The protocol-level encryption settings used on the server side. This must be a <link linkend="python.Encryption.ServerSSLOptions">ServerSSLOptions</link> instance. </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        if not isinstance(server_verify, ServerCertificateVerifier) and not isinstance(server_verify, ServerNoneVerifier) and server_verify != None:
            raise ValueError, "server_verify must be either ServerCertificateVerifier, ServerNoneVerifier or None"

        if not isinstance(client_verify, ClientCertificateVerifier) and not isinstance(client_verify, ClientNoneVerifier) and client_verify != None:
            raise ValueError, "client_verify must be either ClientCertificateVerifier, ClientNoneVerifier or None"

        if not client_certificate_generator:
            raise ValueError, "client_certificate_generator cannot be None"

        if isinstance(client_certificate_generator, DynamicCertificate) and isinstance(server_certificate_generator, DynamicCertificate):
            raise ValueError, "Both client_certificate_generator and server_certificate_generator cannot be DynamicCertificate"

        if not isinstance(client_ssl_options, ClientSSLOptions) and client_ssl_options != None:
            raise ValueError, "client_ssl_options must be either ClientSSLOptions, or None"

        if not isinstance(server_ssl_options, ServerSSLOptions) and server_ssl_options != None:
            raise ValueError, "server_ssl_options must be either ServerSSLOptions, or None"

        super(TwoSidedEncryption, self).__init__(client_security=SSL_FORCE_SSL, server_security=SSL_FORCE_SSL, client_certificate_generator=client_certificate_generator, server_certificate_generator=server_certificate_generator, client_verify=client_verify, server_verify=server_verify, client_ssl_options=client_ssl_options, server_ssl_options=server_ssl_options)
        super(TwoSidedEncryption, self).setup(self)

# Local Variables:
# mode: python
# indent-tabs-mode: nil
# python-indent: 8
# End:
