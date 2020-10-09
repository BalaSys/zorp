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

"""<module maturity="stable">
<summary>
  Proxy for the HyperText Transfer Protocol.
</summary>
<description>
  <para>
    The Http module defines the classes constituting the proxy for the HyperText Transfer Protocol (HTTP). HTTP is the protocol the Web is based on, therefore it is the most frequently used protocol on the Internet. It is used to access different kinds of content from the Web. The type of content retrieved via HTTP is not restricted, it can range from simple text files to hypertext files and multimedia formats like pictures, videos or audio files.
  </para>
  <section>
    <title>The HTTP protocol</title>
    <para>
      HTTP is an open application layer protocol for hypermedia
      information systems. It basically allows an open-ended
      set of methods to be applied to resources identified by
      Uniform Resource Identifiers (URIs).
    </para>
    <section>
      <title>Protocol elements</title>
      <para>
        HTTP is a text based protocol where a client sends a request
        comprising of a METHOD, an URI and associated meta information
        represented as MIME-like headers, and possibly a data attachment.
        The server responds with a status code, a set of headers, and
        possibly a data attachment. Earlier protocol versions perform a single
        transaction in a single TCP connection, HTTP/1.1 introduces
        persistency where a single TCP connection can be reused to perform
        multiple transactions.
      </para>
      <para>
        An HTTP method is a single word - usually spelled in capitals -
        instructing the server to apply a function to the
        resource specified by the URI. Commonly used HTTP methods
        are "GET", "POST" and "HEAD". HTTP method names
        are not restricted in any way, other HTTP based protocols
        (such as WebDAV) add new methods to the protocol while
        keeping the general syntax intact.
      </para>
      <para>
        Headers are part of both the requests and the responses. Each
        header consists of a name followed by a colon (':') and a
        field value. These headers are used to specify
        content-specific and protocol control information.
      </para>
      <para>
        The response to an HTTP request starts with an HTTP status
        line informing the client about the result of the operation
        and an associated message. The result is represented by
        three decimal digits, the possible values are defined in the
        HTTP RFCs.
      </para>
    </section>
    <section>
      <title>Protocol versions</title>
      <para>
        The protocol has three variants, differentiated by their
        version number. Version 0.9 is a very simple protocol which
        allows a simple octet-stream to be transferred without any
        meta information (e.g.: no headers are associated with requests
        or responses).
      </para>
      <para>
        Version 1.0 introduces MIME-like headers in both requests
        and responses; headers are used to control both the
        protocol (e.g.: the "Connection" header) and to give
        information about the content being transferred (e.g.:
        the "Content-Type" header). This version has also introduced the
        concept of name-based virtual hosts.
      </para>
      <para>
        Building on the success of HTTP/1.0, version 1.1 of the
        protocol adds persistent connections (also referred to as
        "connection keep-alive") and improved proxy control.
      </para>
    </section>
    <section>
      <title>Bulk transfer</title>
      <para>
        Both requests and responses might have an associated data blob, also
        called an entity in HTTP terminology. The size of the entity is determined
        using one of three different methods:</para>
        <orderedlist>
          <listitem>
            <para>
              The complete size of the entity is sent as a
              header (the Content-Length header).
            </para>
          </listitem>
          <listitem>
            <para>
              The transport layer connection is terminated when transfer of the blob
              is completed (used by HTTP/0.9 and might be used in HTTP/1.1 in
              non-persistent mode).
            </para>
          </listitem>
          <listitem>
            <para>
              Instead of specifying the complete length, smaller chunks of
              the complete blob are transferred, and each chunk is prefixed
              with the size of that specific chunk. The end of the stream is
              denoted by a zero-length chunk. This mode is also called
              chunked encoding and is specified by the Transfer-Encoding
              header.
            </para>
          </listitem>
        </orderedlist>
      <example>
        <title>Example HTTP transaction</title>
        <synopsis>GET /index.html HTTP/1.1
Host: www.example.com
Connection: keep-alive
User-Agent: My-Browser-Type 6.0

HTTP/1.1 200 OK
Connection: close
Content-Length: 14

&lt;html&gt;
&lt;/html&gt;</synopsis>
      </example>
    </section>
  </section>
  <section>
    <title>Proxy behavior</title>
      <para>
        The default low-level proxy implementation (<link linkend="python.Http.AbstractHttpProxy">AbstractHttpProxy</link>) denies all requests by default. Different requests and/or responses can be enabled by using one of the several predefined proxy classes which are suitable for most tasks. Alternatively, a custom proxy class can be derived from AbstractHttpProxy and the requests and responses enabled individually using different attributes.
      </para>
      <para>
      Several examples and considerations on how to enable virus filtering in the HTTP traffic are discussed in the
        Technical White Paper and Tutorial <emphasis>Virus filtering in HTTP</emphasis>, available at the BalaSys Documentation Page <link xmlns:ns1="http://www.w3.org/1999/xlink" ns1:href="http://www.balasys.hu/documentation/">http://www.balasys.hu/documentation/</link>.
      </para>
      <section>
        <title>Transparent and non-transparent modes</title>
          <para>
            HttpProxy is able to operate both in transparent and non-transparent mode.
            In transparent mode, the client does not notice (or even know) that it is communicating through a proxy. The client communicates using normal server-style requests.
          </para>
          <para>
            In non-transparent mode, the address and
            the port of the proxy server must be set on the client.
            In this case the client sends proxy-style requests to the proxy.
          </para>
          <example>
            <title>Proxy style HTTP query</title>
            <synopsis>GET http://www.example.com/index.html HTTP/1.1
Host: www.example.com
Connection: keep-alive
User-Agent: My-Browser-Type 6.0

HTTP/1.1 200 OK
Connection: close
Content-Length: 14

&lt;html&gt;
&lt;/html&gt;</synopsis>
          </example>
        <para>
          In non-transparent mode it is possible to request the use of the SSL protocol through the proxy, which means the client communicates with the proxy using the HTTP protocol, but the proxy uses HTTPS to communicate with the server. This technique is called data tunneling.
        </para>
        <example>
          <title>Data tunneling with connect method</title>
          <synopsis>CONNECT www.example.com:443 HTTP/1.1
Host: www.example.com
User-agent: My-Browser-Type 6.0

HTTP/1.0 200 Connection established
Proxy-agent: My-Proxy/1.1</synopsis>
        </example>
      </section>
      <section xml:id="http_policies">
        <title>Configuring policies for HTTP requests and responses</title>
        <para>
          Changing the default behavior of requests is possible using the
          <parameter>request</parameter> attribute. This hash is indexed by the HTTP method
          names (e.g.: GET or POST). The <parameter>response</parameter> attribute (indexed by the request method and the response code) enables the control of HTTP responses. The possible actions are described in the following tables. See also <xref linkend="proxy_policies"/>. When looking up entries of the <parameter>response</parameter> attribute hash, the lookup precedence described in <xref linkend="proxy_response_codes"/> is used.

          <inline type="actiontuple" target="action.http.req"/>
          <inline type="actiontuple" target="action.http.rsp"/>
        </para>
        <example>
          <title>Implementing URL filtering in the HTTP proxy</title>
          <para>
          This example calls the filterURL function (defined in the example) whenever a HTTP GET request is received. If the requested URL is 'http://www.disallowedsite.com', the request is rejected and an error message is sent to the client.
          </para>
          <synopsis>class DmzHTTP(HttpProxy):
        def config(self):
                HttpProxy.config(self)
                self.request["GET"] = (HTTP_REQ_POLICY, self.filterURL)

        def filterURL(self, method, url, version):
                if (url == "http://www.disallowedsite.com"):
                        self.error_info = 'Access of this content is denied by the local policy.'
                        return HTTP_REQ_REJECT
                return HTTP_REQ_ACCECT</synopsis>
        </example>
        <example>
          <title>404 response filtering in HTTP</title>
          <para>
          In this example the 404 response code to GET requests is rejected, and a custom error message is returned to the clients instead.
          </para>
          <synopsis>class DmzHTTP(HttpProxy):
        def config(self):
                HttpProxy.config(self)
                self.response["GET", "404"] = (HTTP_RSP_POLICY, self.filter404)

        def filter404(self, method, url, version, response):
                self.error_status = 404
                self.error_info = "Requested page was not accessible."
                return HTTP_RSP_REJECT</synopsis>
        </example>

      </section>

      <section xml:id="http_header_policies">
        <title>Configuring policies for HTTP headers</title>
        <para>
          Both request and response headers can be modified by the proxy during
          the transfer. New header lines can be inserted, entries can be modified
          or deleted. To change headers in the requests and responses use the
          <parameter>request_header</parameter> hash or the <parameter>response_header</parameter> hash, respectively.
        </para>
        <para>
          Similarly to the request hash, these hashes are indexed by
          the header name (like "User-Agent") and contain an
          actiontuple describing the action to take.
        </para>
        <para>
          By default, the proxy modifies only the "Host", "Connection", "Proxy-Connection" and "Transfer-Encoding" headers. "Host" headers need to be changed when the proxy modifies the URL; "(Proxy-)Connection" is changed when the proxy turns connection keep-alive on/off; "Transfer-Enconding" is changed to enable chunked encoding.

          <inline type="actiontuple" target="action.http.hdr"/>

        </para>
        <example>
          <title>Header filtering in HTTP</title>
          <para>
          The following example hides the browser used by the client by replacing the value of the User-Agent header to Lynx in all requests. The use of cookies is disabled as well.
          </para>
          <synopsis>class MyHttp(HttpProxy):
        def config(self):
                HttpProxy.config(self)
                self.request_header["User-Agent"] = (HTTP_HDR_CHANGE_VALUE, "Lynx 2.4.1")
                self.request_header["Cookie"] = (HTTP_HDR_POLICY, self.processCookies)
                self.response_header["Set-Cookie"] = (HTTP_HDR_DROP,)

        def processCookies(self, name, value):
                # You could change the current header in self.current_header_name
                # or self.current_header_value, the current request url is
                # in self.request_url
                return HTTP_HDR_DROP</synopsis>
        </example>
      </section>
      <section>
        <title>Redirecting URLs</title>
        <para>
          URLs or sets of URLs can be easily rejected or redirected to
          a local mirror by modifying some attributes during request
          processing.
        </para>
        <para>
          When an HTTP request is received, normative policy chains are processed
          (<parameter>self.request</parameter>, <parameter>self.request_header</parameter>). Policy callbacks for certain events can be configured with the HTTP_REQ_POLICY or HTTP_HDR_POLICY directives. Any of these callbacks may change the <parameter>request_url</parameter> attribute, instructing the proxy to fetch a page different from the one specified by the browser. Please note that this is transparent
          to the user and does not change the URL in the browser.
        </para>
        <example>
          <title>URL redirection in HTTP proxy</title>
          <para>
          This example redirects all HTTP GET requests to the 'http://www.example.com/' URL by modifying the value of the requested URL.
          </para>
          <synopsis>class MyHttp(HttpProxy):
        def config(self):
                HttpProxy.config(self)
                self.request["GET"] = (HTTP_REQ_POLICY, self.filterURL)

        def filterURL(self, method, url, version):
                self.request_url = "http://www.example.com/"
                return HTTP_REQ_ACCEPT</synopsis>
        </example>
        <example>
          <title>Redirecting HTTP to HTTPS</title>
          <para>
          This example redirects all incoming HTTP connections to an HTTPS URL.
          </para>
          <synopsis>class HttpProxyHttpsredirect(HttpProxy):
        def config(self):
                HttpProxy.config(self)
                self.error_silent = TRUE
                self.request["GET"] = (HTTP_REQ_POLICY, self.reqRedirect)

        def reqRedirect(self, method, url, version):
                self.error_status = 301
                #self.error_info = 'HTTP/1.0 301 Moved Permanently'
                self.error_headers="Location: https://%s/" % self.request_url_host
                return HTTP_REQ_REJECT</synopsis>
        </example>
      </section>
      <section>
        <title>Request types</title>
        <para>
          Zorp differentiates between two request types: server requests and proxy request.</para>
          <itemizedlist>
            <listitem>
                <para>Server requests are sent by browsers directly communicating with HTTP
                  servers. These requests include an URL relative to the server
                  root (e.g.: /index.html), and a 'Host' header indicating which
                  virtual server to use.</para>
            </listitem>
            <listitem>
                <para>Proxy requests are used when the browser
                  communicates with an HTTP proxy. These requests include a fully
                  specified URL (e.g.: http://www.example.com/index.html).</para>
            </listitem>
          </itemizedlist>
        <para>Zorp determines the type of the incoming request from the request URL, even if the Proxy-connection header exist.
          As there is no clear distinction between the two request types,
          the type of the request cannot always be accurately detected automatically, though all
          common cases are covered.
        </para>
        <para>
          Requests are handled differently in transparent and
          non-transparent modes.
        </para>
        <itemizedlist>
            <listitem>
                <para>A transparent HTTP proxy (<parameter>transparent_mode</parameter> attribute is TRUE) is
                      meant to be installed in front of a network where clients do not
                      know about the presence of the firewall. In this case the proxy
                      expects to see server type requests only. If clients communicate
                      with a real HTTP proxy through the firewall, proxy type requests
                      must be explicitly enabled using the <parameter>permit_proxy_requests</parameter>
                      attribute, or transparent mode has to be used.</para>
            </listitem>
            <listitem>
                <para>The use of non-transparent HTTP proxies (<parameter>transparent_mode</parameter>
                      attribute is FALSE) must be configured in web browsers behind
                      the firewall. In this case Zorp expects proxy requests only, and
                      emits server requests (assuming <parameter>parent_proxy</parameter> is not set).</para>
            </listitem>
          </itemizedlist>
      </section>
      <section>
        <title>Using parent proxies</title>
        <para>
          Parent proxies are non-transparent HTTP proxies used behind Zorp. Two things have to be set in order to use parent proxies. First,
          select a router which makes the proxy connect to the
          parent proxy, this can be either InbandRouter() or
          DirectedRouter(). Second, set the <parameter>parent_proxy</parameter> and
          <parameter>parent_proxy_port</parameter> attributes in the HttpProxy class. Setting
          these attributes results in proxy requests to be emitted to the
          target server both in transparent and non-transparent mode.
        </para>
        <para>
          The parent proxy attributes can be set both in the
          configuration phase (e.g.: config() event), or later on a
          per-request basis. This is possible because the proxy re-connects.
        </para>
        <example>
          <title>Using parent proxies in HTTP</title>
          <para>In this example the MyHttp proxy class uses a parent proxy. For this the domain name and address of the parent proxy is specified, and a service using an InbandRouter is created.</para>
          <synopsis>class MyHttp(HttpProxy):
        def config(self):
                HttpProxy.config(self)
                self.parent_proxy = "proxy.example.com"
                self.parent_proxy_port = 3128

def instance():
        Service("http", MyHttp, router=InbandRouter())
        Listener(SockAddrInet('10.0.0.1', 80), "http")</synopsis>
        </example>
      </section>
      <section>
        <title>FTP over HTTP</title>
        <para>
          In non-transparent mode it is possible to let Zorp process ftp://
          URLs, effectively translating HTTP requests to FTP requests on
          the fly. This behaviour can be enabled by setting
          <parameter>permit_ftp_over_http</parameter> to TRUE and adding port 21 to
          <parameter>target_port_range</parameter>. Zorp currently supports passive mode
          transfers only.
        </para>
      </section>
      <section>
        <title>Error messages</title>
        <para>
          There are cases when the HTTP proxy must return an error page to
          the client to indicate certain error conditions. These error
          messages are stored as files in the directory specified by the
          <parameter>error_files_directory</parameter> attribute, and can be customized by
          changing the contents of the files in this directory.
        </para>
        <para>
          Each file contains plain HTML text, but some special macros are
          provided to dynamically add information to the error page. The
          following macros can be used:

          <itemizedlist>
            <listitem><para><emphasis>@INFO@</emphasis> -- further error information as provided by the proxy</para></listitem>
            <listitem><para><emphasis>@VERSION@</emphasis> -- Zorp version number</para></listitem>
            <listitem><para><emphasis>@DATE@</emphasis> -- current date</para></listitem>
            <listitem><para><emphasis>@HOST@</emphasis> -- hostname of Zorp</para></listitem>
          </itemizedlist>
        </para>
        <para>
          It is generally recommended not to display error messages to
          untrusted clients, as they may leak confidential information. To
          turn error messages off, set the <parameter>error_silent</parameter> attribute to TRUE, or
          strip error files down to a minimum.
        </para>
        <note>
          <para>
          The language of the messages can be set using the <parameter>config.options.language</parameter> global option, or individually for every Http proxy using the <parameter>language</parameter> parameter.
          See <xref linkend="appendix_globaloptions"/> for details.
          </para>
        </note>
      </section>
      <section xml:id="http_stacking">
        <title>Stacking</title>
        <para>
          HTTP supports stacking proxies for both request and response
          entities (e.g.: data bodies). This is controlled by the
          <parameter>request_stack</parameter> and <parameter>response_stack</parameter> attribute hashes. See also <xref linkend="proxy_stacking"/>.
        </para>
        <para>
          There are two stacking modes available: HTTP_STK_DATA sends only
          the data portion to the downstream proxy, while HTTP_STK_MIME also sends
          all header information to make it possible to process the data
          body as a MIME envelope. Please note that while it is possible to
          change the data part in the stacked proxy, it is not possible to
          change the MIME headers - they can be modified only by the HTTP proxy.
          The possible parameters are listed in the following tables.
        </para>
        <inline type="actiontuple" target="action.http.stk"/>
<!--        <example>
          <title>Proxy stacking in HTTP</title>
          <para>
          In this example all responses received are passed to VBusterProxy to for virus checking.
          </para>
          <synopsis>class MyHttp(HttpProxy):
        def config(self):
                HttpProxy.config(self)
                self.response_stack["GET"] = (HTTP_STK_DATA, (Z_STACK_PROXY, VBusterProxy))</synopsis>
        </example>-->
        <para>
          Please note that stacking is skipped altogether if there is no
          body in the message.
        </para>
      </section>
        <section>
        <title>Webservers returning data in 205 responses</title>
        <para>
        Certain webserver applications may return data entities in 205 responses. This is explicitly prohibited
        by the RFCs, but Zorp permits such responses for interoperability reasons.
        </para>
        </section>
        <section xml:id="zorp_http_urlfiltering" condition="zorp">
            <title>URL filtering in HTTP</title>
            <para>Starting with version 3.3FR1, Zorp supports category-based URL filtering using a regularly updated database.</para>
            <itemizedlist>
                <listitem>
                    <para>To configure URL-filtering, see <xref linkend="zorp_http_urlfiltering_configuring"/>.</para>
                </listitem>
                <listitem>
                    <para>For the list of categories available by default, see <xref linkend="zorp_http_urlfiltering_categories"/>.</para>
                </listitem>
                <listitem>
                    <para>To customize or expand the URL-database, see <xref linkend="zorp_http_urlfiltering_manual"/>.</para>
                </listitem>
            </itemizedlist>
            <section xml:id="zorp_http_urlfiltering_configuring">
                <title>Configuring URL-filtering in HTTP</title>
                    <para>The URLs and domains in the database are organized into thematic categories like <parameter>adult</parameter>, <parameter>news</parameter>, <parameter>jobsearch</parameter>, etc.</para>
                    <para>To enable url-filtering, set the <parameter>enable_url_filter</parameter> and <parameter>enable_url_filter_dns</parameter> options to <parameter>TRUE</parameter>. The <parameter>enable_url_filter_dns</parameter> option is needed only to ensure that a domain or URL is correctly categorized even when it is listed in the database using its domain name, but the client tries to access it with its IP address (or vice-versa).</para>
                    <note>
                        <para>URL-filtering is handled by the Zorp Http proxy, without the need of using ZCV. The URL-filtering capability of Zorp is available only after purchasing the <parameter>url-filter</parameter> license option.</para>
                        <para>Updates to the URL database are automatically downloaded daily from the BalaSys website using the <command>zavupdate</command> utility. </para>
                    </note>
             <para>Access to specific categories can be set using the <parameter>url_category</parameter> option, which is a hash indexed by the name of the category. The following actions are possible:</para>
             <inline type="actiontuple" target="action.http.url"/>
            <example>
                <title>URL-filtering example</title>
                <para>The following example blocks several categories and accepts the rest. For a complete list of categories, see <xref linkend="zorp_http_urlfiltering_categories"/>.</para>
                <synopsis>class MyHTTPUrlFilter(HttpProxy):
    def config(self):
        HttpProxy.config(self)
        self.enable_url_filter=TRUE
        self.enable_url_filter_dns=TRUE
        self.url_category['adult']=(HTTP_URL_REJECT, (403, "Adult website",))
        self.url_category['porn']=(HTTP_URL_REJECT, (403, "Porn website",))
        self.url_category['malware']=(HTTP_URL_REJECT, (403, "Site contains malware",))
        self.url_category['phishing']=(HTTP_URL_REJECT, (403, "Phishing site",))
        self.url_category['warez']=(HTTP_URL_REJECT, (403, "Warez site",))
        self.url_category['*']=(HTTP_URL_ACCEPT,)</synopsis>
        <para>The following example redirects access to online gaming sites to a dummy website.</para>
                <synopsis>class MyHTTPUrlFilter(HttpProxy):
    def config(self):
        HttpProxy.config(self)
        self.enable_url_filter=TRUE
        self.enable_url_filter_dns=TRUE
        self.url_category['onlinegames']=(HTTP_URL_REDIRECT, "http://example.com")
        self.url_category['*']=(HTTP_URL_ACCEPT,)</synopsis>
            </example>
            </section>
            <section xml:id="zorp_http_urlfiltering_categories">
                <title>List of URL-filtering categories</title>
                <para>The Zorp URL database contains the following thematic categories by default.</para>
                <itemizedlist>
        <listitem>
            <para><emphasis>abortion</emphasis>: Abortion information excluding when related to religion</para>
        </listitem>
        <listitem>
            <para><emphasis>ads</emphasis>: Advert servers and banned URLs</para>
        </listitem>
        <listitem>
            <para><emphasis>adult</emphasis>: Sites containing adult material such as swearing but not porn</para>
        </listitem>
        <listitem>
            <para><emphasis>aggressive</emphasis>: Similar to violence but more promoting than depicting</para>
        </listitem>
        <listitem>
            <para><emphasis>antispyware</emphasis>: Sites that remove spyware</para>
        </listitem>
        <listitem>
            <para><emphasis>artnudes</emphasis>: Art sites containing artistic nudity</para>
        </listitem>
        <listitem>
            <para><emphasis>astrology</emphasis>: Astrology websites</para>
        </listitem>
        <listitem>
            <para><emphasis>audio-video</emphasis>: Sites with audio or video downloads</para>
        </listitem>
        <listitem>
            <para><emphasis>banking</emphasis>: Banking websites</para>
        </listitem>
        <listitem>
            <para><emphasis>beerliquorinfo</emphasis>: Sites with information only on beer or liquors</para>
        </listitem>
        <listitem>
            <para><emphasis>beerliquorsale</emphasis>: Sites with beer or liquors for sale</para>
        </listitem>
        <listitem>
            <para><emphasis>blog</emphasis>: Journal/Diary websites</para>
        </listitem>
        <listitem>
            <para><emphasis>cellphones</emphasis>: stuff for mobile/cell phones</para>
        </listitem>
        <listitem>
            <para><emphasis>chat</emphasis>: Sites with chat rooms etc</para>
        </listitem>
        <listitem>
            <para><emphasis>childcare</emphasis>: Sites to do with childcare</para>
        </listitem>
        <listitem>
            <para><emphasis>cleaning</emphasis>: Sites to do with cleaning</para>
        </listitem>
        <listitem>
            <para><emphasis>clothing</emphasis>: Sites about and selling clothing</para>
        </listitem>
        <listitem>
            <para><emphasis>contraception</emphasis>: Information about contraception</para>
        </listitem>
        <listitem>
            <para><emphasis>culinary</emphasis>: Sites about cooking et al</para>
        </listitem>
        <listitem>
            <para><emphasis>dating</emphasis>: Sites about dating</para>
        </listitem>
        <listitem>
            <para><emphasis>desktopsillies</emphasis>: Sites containing screen savers, backgrounds, cursers, pointers, desktop themes and similar timewasting and potentially dangerous content</para>
        </listitem>
        <listitem>
            <para><emphasis>dialers</emphasis>: Sites with dialers such as those for pornography or trojans</para>
        </listitem>
        <listitem>
            <para><emphasis>drugs</emphasis>: Drug related sites</para>
        </listitem>
        <listitem>
            <para><emphasis>ecommerce</emphasis>: Sites that provide online shopping</para>
        </listitem>
        <listitem>
            <para><emphasis>entertainment</emphasis>: Sites that promote movies, books, magazine, humor</para>
        </listitem>
        <listitem>
            <para><emphasis>filehosting</emphasis>: Sites to do with filehosting</para>
        </listitem>
        <listitem>
            <para><emphasis>frencheducation</emphasis>: Sites to do with french education</para>
        </listitem>
        <listitem>
            <para><emphasis>gambling</emphasis>: Gambling sites including stocks and shares</para>
        </listitem>
        <listitem>
            <para><emphasis>games</emphasis>: Game related sites</para>
        </listitem>
        <listitem>
            <para><emphasis>gardening</emphasis>: Gardening sites</para>
        </listitem>
        <listitem>
            <para><emphasis>government</emphasis>: Military and schools etc</para>
        </listitem>
        <listitem>
            <para><emphasis>guns</emphasis>: Sites with guns</para>
        </listitem>
        <listitem>
            <para><emphasis>hacking</emphasis>: Hacking/cracking information</para>
        </listitem>
        <listitem>
            <para><emphasis>homerepair</emphasis>: Sites about home repair</para>
        </listitem>
        <listitem>
            <para><emphasis>hygiene</emphasis>: Sites about hygiene and other personal grooming related stuff</para>
        </listitem>
        <listitem>
            <para><emphasis>instantmessaging</emphasis>: Sites that contain messenger client download and web-based messaging sites</para>
        </listitem>
        <listitem>
            <para><emphasis>jewelry</emphasis>: Sites about and selling jewelry</para>
        </listitem>
        <listitem>
            <para><emphasis>jobsearch</emphasis>: Sites for finding jobs</para>
        </listitem>
        <listitem>
            <para><emphasis>kidstimewasting</emphasis>: Sites kids often waste time on</para>
        </listitem>
        <listitem>
            <para><emphasis>mail</emphasis>: Webmail and email sites</para>
        </listitem>
        <listitem>
            <para><emphasis>marketingware</emphasis>: Sites about marketing products</para>
        </listitem>
        <listitem>
            <para><emphasis>medical</emphasis>: Medical websites</para>
        </listitem>
        <listitem>
            <para><emphasis>mixed_adult</emphasis>: Mixed adult content sites</para>
        </listitem>
        <listitem>
            <para><emphasis>mobile-phone</emphasis>: Sites to do with mobile phones</para>
        </listitem>
        <listitem>
            <para><emphasis>naturism</emphasis>: Sites that contain nude pictures and/or promote a nude lifestyle</para>
        </listitem>
        <listitem>
            <para><emphasis>news</emphasis>: News sites</para>
        </listitem>
        <listitem>
            <para><emphasis>onlineauctions</emphasis>: Online auctions</para>
        </listitem>
        <listitem>
            <para><emphasis>onlinegames</emphasis>: Online gaming sites</para>
        </listitem>
        <listitem>
            <para><emphasis>onlinepayment</emphasis>: Online payment sites</para>
        </listitem>
        <listitem>
            <para><emphasis>personalfinance</emphasis>: Personal finance sites</para>
        </listitem>
        <listitem>
            <para><emphasis>pets</emphasis>: Pet sites</para>
        </listitem>
        <listitem>
            <para><emphasis>phishing</emphasis>: Sites attempting to trick people into giving out private information</para>
        </listitem>
        <listitem>
            <para><emphasis>porn</emphasis>: Pornography</para>
        </listitem>
        <listitem>
            <para><emphasis>proxy</emphasis>: Sites with proxies to bypass filters</para>
        </listitem>
        <listitem>
            <para><emphasis>radio</emphasis>: non-news related radio and television</para>
        </listitem>
        <listitem>
            <para><emphasis>religion</emphasis>: Sites promoting religion</para>
        </listitem>
        <listitem>
            <para><emphasis>ringtones</emphasis>: Sites containing ring tones, games, pictures and other</para>
        </listitem>
        <listitem>
            <para><emphasis>searchengines</emphasis>: Search engines such as google</para>
        </listitem>
        <listitem>
            <para><emphasis>sect</emphasis>: Sites about religious groups</para>
        </listitem>
        <listitem>
            <para><emphasis>sexuality</emphasis>: Sites dedicated to sexuality, possibly including adult material</para>
        </listitem>
        <listitem>
            <para><emphasis>shopping</emphasis>: Shopping sites</para>
        </listitem>
        <listitem>
            <para><emphasis>socialnetworking</emphasis>: Social networking websites</para>
        </listitem>
        <listitem>
            <para><emphasis>sportnews</emphasis>: Sport news sites</para>
        </listitem>
        <listitem>
            <para><emphasis>sports</emphasis>: All sport sites</para>
        </listitem>
        <listitem>
            <para><emphasis>spyware</emphasis>: Sites who run or have spyware software to download</para>
        </listitem>
        <listitem>
            <para><emphasis>updatesites</emphasis>: Sites where software updates are downloaded from including virus sigs</para>
        </listitem>
        <listitem>
            <para><emphasis>vacation</emphasis>: Sites about going on holiday</para>
        </listitem>
        <listitem>
            <para><emphasis>violence</emphasis>: Sites containing violence</para>
        </listitem>
        <listitem>
            <para><emphasis>virusinfected</emphasis>: Sites who host virus infected files</para>
        </listitem>
        <listitem>
            <para><emphasis>warez</emphasis>: Sites with illegal pirate software</para>
        </listitem>
        <listitem>
            <para><emphasis>weather</emphasis>: Weather news sites and weather related</para>
        </listitem>
        <listitem>
            <para><emphasis>weapons</emphasis>: Sites detailing or selling weapons</para>
        </listitem>
        <listitem>
            <para><emphasis>webmail</emphasis>: Just webmail sites</para>
        </listitem>
        <listitem>
            <para><emphasis>whitelist</emphasis>: Contains site suitable for kids</para>
        </listitem>
</itemizedlist>
            </section>
            <section xml:id="zorp_http_urlfiltering_manual">
                 <title>Customizing the URL database</title>
                 <para>To customize the database, you have to manually edit the relevant files of the database. The URL database is located on the Zorp hosts under the <filename>/etc/zorp/urlfilter/</filename> directory. Every thematic category is subdirectory containing two files called <filename>domains</filename> and <filename>urls</filename>. These files contain the list of domains (e.g., <parameter>example.com</parameter>) and URLs (e.g., <parameter>example.com/news/</parameter>) that fall into the specific category. Optionally, the subdirectory may contain a third file called <filename>expressions</filename>, where more complex rules can be defined using regular expressions.</para>
                 <itemizedlist>
                     <listitem>
                         <para>To to allow access (whitelist) to a domain or URL, add it to the <filename>domains</filename> or <filename>urls</filename> file of the <parameter>whitelist</parameter> category. Do not forget to configure your Http proxies to permit access to the domains of the <parameter>whitelist</parameter> category.</para>
                         <warning>
                             <para>Deleting a domain from a category is not equivalent to whitelisting. Deleted domains will be re-added to their original category after the next database update.</para>
                         </warning>
                     </listitem>
                     <listitem>
                         <para>To add a new URL or domain to an existing category, create a new subdirectory under <filename>/etc/zorp/urlfilter/</filename>, create the <filename>domains</filename> and <filename>urls</filename> files for this new category, and add the domain or URL (without the <parameter>http://www.</parameter> prefix) to the <filename>domains</filename> or <filename>urls</filename>file. Zorp will automatically add these sites to the specific category after the next daily database update, or when the <command>zufupdate</command> command is executed.</para>
                     </listitem>
                     <listitem>
                         <para>To create a new category, create a new subdirectory under <filename>/etc/zorp/urlfilter/</filename>, create the <filename>domains</filename> and <filename>urls</filename> files for this new category, and add domains and URLs  to these files. Do not forget to configure your Http proxies to actually use the new category.</para>
                     </listitem>
                 </itemizedlist>
                 <warning>
                     <para>Manual changes to the URL database are not applied automatically, they become effective only after the next daily database update, or when the <command>zufupdate</command> command is executed.</para>
                 </warning>
                 <note>
                     <para>Manual changes are automatically merged with the original database during database updates.</para>
                     <para>If you are using the URL-filter database on several Zorp hosts and modify the database manually, make sure to copy your changes to the other hosts as well.  </para>
                 </note>
            </section>
        </section>
  </section>
  <section>
    <title>Related standards</title>
    <para>
      <itemizedlist>
        <listitem>
          <para>
            The Hypertext Transfer Protocol -- HTTP/1.1 protocol is described in RFC 2616.
          </para>
        </listitem>
        <listitem>
          <para>
            The Hypertext Transfer Protocol -- HTTP/1.0 protocol is described in RFC 1945.
          </para>
        </listitem>
      </itemizedlist>
    </para>
  </section>
</description>
<metainfo>
  <enums>
    <enum maturity="stable" id="enum.http.req">
      <summary>
        HTTP request actions
      </summary>
      <description>
        These values specify the action to take as a given request
        arrives. They are used as the first value in the tuple
      </description>
      <item><name>HTTP_REQ_ACCEPT</name></item>
      <item><name>HTTP_REQ_DENY</name></item>
      <item><name>HTTP_REQ_REJECT</name></item>
      <item><name>HTTP_REQ_ABORT</name></item>
      <item><name>HTTP_REQ_POLICY</name></item>
    </enum>
    <enum maturity="stable" id="enum.http.rsp">
      <description>
      </description>
      <item><name>HTTP_RSP_ACCEPT</name></item>
      <item><name>HTTP_RSP_DENY</name></item>
      <item><name>HTTP_RSP_REJECT</name></item>
      <item><name>HTTP_RSP_ABORT</name></item>
      <item><name>HTTP_RSP_POLICY</name></item>
    </enum>
    <enum maturity="stable" id="enum.http.hdr">
      <description>
      </description>
      <item><name>HTTP_HDR_ACCEPT</name></item>
      <item><name>HTTP_HDR_ABORT</name></item>
      <item><name>HTTP_HDR_DROP</name></item>
      <item><name>HTTP_HDR_POLICY</name></item>
      <item><name>HTTP_HDR_CHANGE_NAME</name></item>
      <item><name>HTTP_HDR_CHANGE_VALUE</name></item>
      <item><name>HTTP_HDR_CHANGE_BOTH</name></item>
      <item><name>HTTP_HDR_CHANGE_REGEXP</name></item>
      <item><name>HTTP_HDR_INSERT</name></item>
      <item><name>HTTP_HDR_REPLACE</name></item>
    </enum>
    <enum maturity="stable" id="enum.http.connection">
      <description>
      </description>
      <item><name>HTTP_CONNECTION_CLOSE</name></item>
      <item><name>HTTP_CONNECTION_KEEPALIVE</name></item>
    </enum>
    <enum maturity="stable" id="enum.http.stk">
      <description>
      </description>
      <item><name>HTTP_STK_NONE</name></item>
      <item><name>HTTP_STK_DATA</name></item>
      <item><name>HTTP_STK_MIME</name></item>
    </enum>
    <enum maturity="stable" id="enum.http.url">
      <description>
      </description>
      <item><name>HTTP_URL_ACCEPT</name></item>
      <item><name>HTTP_URL_REJECT</name></item>
      <item><name>HTTP_URL_REDIRECT</name></item>
    </enum>
  </enums>
  <actiontuples>
    <actiontuple maturity="stable" id="action.http.req" action_enum="enum.http.req">
      <description>
        Action codes for HTTP requests
      </description>
      <tuple action="HTTP_REQ_ACCEPT" display_name="Accept the request">
        <args/>
        <description>
          <para>
             Allow the request to pass.
          </para>
        </description>
      </tuple>
      <tuple action="HTTP_REQ_REJECT" display_name="Reject the request">
        <args>
          <string display_name="Reason for the rejection"/>
        </args>
        <description>
          <para>
            Reject the request. The reason for the rejection can be specified in the optional second argument.
          </para>
        </description>
      </tuple>
      <tuple action="HTTP_REQ_ABORT" display_name="Terminate the connection">
        <args/>
        <description>
          <para>
            Terminate the connection.
          </para>
        </description>
      </tuple>
      <tuple action="HTTP_REQ_POLICY" display_name="Call a user defined decision function">
        <args>
          <METHOD/>
        </args>
        <description>
          <para>
            Call the function specified to make a decision about the event. The function receives four arguments: self, method, url, version. See <xref linkend="proxy_policies"/> for details.
          </para>
        </description>
      </tuple>
    </actiontuple>
    <actiontuple maturity="stable" id="action.http.rsp" action_enum="enum.http.rsp">
      <description>
        Action codes for HTTP responses
      </description>
      <tuple action="HTTP_RSP_ACCEPT" display_name="Allow the response">
        <args/>
        <description>
          Allow the response to pass.
        </description>
      </tuple>
      <tuple action="HTTP_RSP_DENY" display_name="Redirect to a policy violation page">
        <args/>
        <description>
          Reject the response and return a policy violation page to the client.
        </description>
      </tuple>
      <tuple action="HTTP_RSP_REJECT" display_name="Redirect to a custom policy violation page">
        <args>
          <string display_name="Error information to display to the client"/>
        </args>
        <description>
           Reject the response and return a policy violation page to the
           client, with error information optionally specified as the
           second argument.
        </description>
      </tuple>
      <tuple action="HTTP_RSP_POLICY" display_name="Call a user defined decision function">
        <args>
          <METHOD/>
        </args>
        <description>
          Call the function specified to make a decision about the event. The function receives five parameters:
          self, method, url, version, response. See <xref linkend="proxy_policies"/> for details.
        </description>
      </tuple>
    </actiontuple>
    <actiontuple maturity="stable" id="action.http.hdr" action_enum="enum.http.hdr">
      <description>
        Action codes for HTTP headers
      </description>
      <tuple action="HTTP_HDR_ABORT" display_name="Terminate the connection">
        <args/>
        <description>
          Terminate the connection.
        </description>
      </tuple>
      <tuple action="HTTP_HDR_ACCEPT" display_name="Accept the header">
        <args/>
        <description>
          Accept the header.
        </description>
      </tuple>
      <tuple action="HTTP_HDR_DROP" display_name="Remove the header">
        <args/>
        <description>
          Remove the header.
        </description>
      </tuple>
      <tuple action="HTTP_HDR_POLICY" display_name="Call a user defined decision function">
        <args>
          <METHOD/>
        </args>
        <description>
          Call the function specified to make a decision about the event. The function receives three parameters:
          self, hdr_name, and hdr_value.
        </description>
      </tuple>
      <tuple action="HTTP_HDR_CHANGE_NAME" display_name="Rename the header">
        <args>
          <string display_name="New name"/>
        </args>
        <description>
          Rename the header to the name specified in the second argument.
        </description>
      </tuple>
      <tuple action="HTTP_HDR_CHANGE_VALUE" display_name="Overwrite the value of the header">
        <args>
          <string display_name="New value"/>
        </args>
        <description>
          Change the value of the header to the value specified in the second argument.
        </description>
      </tuple>
      <tuple action="HTTP_HDR_CHANGE_BOTH" display_name="Change both name and value">
        <args>
            <string display_name="New name"/>
            <string display_name="New value"/>
        </args>
        <description>
          Change both the name and value of the header to the values specified in the second and third arguments, respectively.
        </description>
      </tuple>
      <tuple action="HTTP_HDR_INSERT" display_name="Insert a new header line">
        <args>
          <string display_name="New header line content"/>
        </args>
        <description>
          Insert a new header defined in the second argument.
        </description>
      </tuple>
      <tuple action="HTTP_HDR_REPLACE" display_name="Replace the header">
        <args>
          <string display_name="New header line content"/>
        </args>
        <description>
          Remove all existing occurrences of a header and replace them with the one specified in the second argument.
        </description>
      </tuple>
    </actiontuple>
    <actiontuple maturity="stable" id="action.http.stk" action_enum="enum.http.stk">
        <description>
        Constants for proxy stacking
        </description>
      <tuple action="HTTP_STK_NONE">
        <args/>
        <description>
        No additional proxy is stacked into the HTTP proxy.
        </description>
      </tuple>
      <tuple action="HTTP_STK_DATA">
        <args>
          <link id="action.zorp.stack"/>
        </args>
        <description>
        The data part of the HTTP traffic is passed to the specified stacked proxy.
        </description>
      </tuple>
      <tuple action="HTTP_STK_MIME">
        <args>
          <link id="action.zorp.stack"/>
        </args>
        <description>
        The data part including header information of the HTTP traffic is passed to the specified stacked proxy.
        </description>
      </tuple>
    </actiontuple>
    <actiontuple maturity="stable" id="action.http.url" action_enum="enum.http.url">
      <description>
        Action codes for URL filtering
      </description>
      <tuple action="HTTP_URL_ACCEPT" display_name="Permit access">
        <args/>
        <description>
          <para>
             Permit access to the URL.
          </para>
        </description>
      </tuple>
      <tuple action="HTTP_URL_REJECT" display_name="Reject the request">
        <args>
          <tuple>
            <integer display_name="Error code"/>
            <string display_name="Reason for the rejection"/>
          </tuple>
        </args>
        <description>
          <para>
            Reject the request. The error code and reason for the rejection can be specified in the optional second and third arguments. See <xref linkend="zorp_http_urlfiltering_configuring"/> for details.
          </para>
        </description>
      </tuple>
      <tuple action="HTTP_URL_REDIRECT" display_name="Redirect the connection">
        <args>
            <string display_name="Redirect to this URL"/>
        </args>
        <description>
          <para>
            Redirect the connection to the URL specified in the second argument.
          </para>
        </description>
      </tuple>
    </actiontuple>
  </actiontuples>
  <constants>
    <constantgroup maturity="stable" id="const.http.log">
      <description>
      </description>
      <item><name>HTTP_DEBUG</name><value>"http.debug"</value></item>
      <item><name>HTTP_INFO</name><value>"http.info"</value></item>
      <item><name>HTTP_ERROR</name><value>"http.error"</value></item>
      <item><name>HTTP_POLICY</name><value>"http.policy"</value></item>
      <item><name>HTTP_REQUEST</name><value>"http.request"</value></item>
      <item><name>HTTP_RESPONSE</name><value>"http.response"</value></item>
      <item><name>HTTP_VIOLATION</name><value>"http.violation"</value></item>
      <item><name>HTTP_ACCOUNTING</name><value>"http.accounting"</value></item>
    </constantgroup>
  </constants>
</metainfo>
</module>"""

from Zorp import *
from Plug import PlugProxy
from Proxy import Proxy, proxyLog
from Matcher import getMatcher

HTTP_URL_REJECT = 1
HTTP_URL_REDIRECT = 2
HTTP_URL_ACCEPT = 3

HTTP_REQ_ACCEPT = 1
HTTP_REQ_DENY = 2
HTTP_REQ_REJECT = 3
HTTP_REQ_ABORT = 4
HTTP_REQ_POLICY = 6
HTTP_REQ_CUSTOM_RESPONSE = 7

HTTP_RSP_ACCEPT = 1
HTTP_RSP_DENY = 2
HTTP_RSP_REJECT = 3
HTTP_RSP_ABORT = 4
HTTP_RSP_POLICY = 6

HTTP_HDR_ACCEPT = 1
HTTP_HDR_ABORT = 4
HTTP_HDR_DROP = 5
HTTP_HDR_POLICY = 6
HTTP_HDR_CHANGE_NAME = 100
HTTP_HDR_CHANGE_VALUE = 101
HTTP_HDR_CHANGE_BOTH = 102
HTTP_HDR_CHANGE_REGEXP = 103
HTTP_HDR_INSERT = 104
HTTP_HDR_REPLACE = 105

HTTP_CONNECTION_CLOSE = 0
HTTP_CONNECTION_KEEPALIVE = 1

HTTP_DEBUG = "http.debug"
HTTP_ERROR = "http.error"
HTTP_POLICY = "http.policy"
HTTP_REQUEST = "http.request"
HTTP_RESPONSE = "http.response"
HTTP_VIOLATION = "http.violation"
HTTP_ACCOUNTING = "http.accounting"

HTTP_STK_NONE = 1
HTTP_STK_DATA = 2
HTTP_STK_MIME = 3
HTTP_STK_POLICY = 4


class AbstractHttpProxy(Proxy):

    """<class maturity="stable" abstract="yes">
    <summary>
      Class encapsulating the abstract HTTP proxy.
    </summary>
    <description>
      <para>
        This class implements an abstract HTTP proxy - it serves as a starting point for customized proxy classes, but is itself not directly usable. Service definitions  should refer to a customized class derived from AbstractHttpProxy, or one of the predefined proxy classes, such as <link linkend="python.Http.HttpProxy">HttpProxy</link> or <link linkend="python.Http.HttpProxyNonTransparent">HttpProxyNonTransparent</link>. AbstractHttpProxy denies all requests by default.
      </para>
    </description>
    <metainfo>
      <attributes>
        <attribute maturity="stable">
          <name>transparent_mode</name>
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
            Set the operation mode of the proxy to transparent
            (TRUE) or non-transparent (FALSE).
          </description>
        </attribute>
        <attribute>
          <name>permit_server_requests</name>
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
            Allow server-type requests in non-transparent mode.
          </description>
        </attribute>
        <attribute>
          <name>permit_proxy_requests</name>
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
          </runtime>
          <description>
            Allow proxy-type requests in transparent mode.
          </description>
        </attribute>
        <attribute>
          <name>permit_ftp_over_http</name>
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
          </runtime>
          <description>
            Allow processing FTP URLs in non-transparent mode.
          </description>
        </attribute>
        <attribute>
          <name>permit_unicode_url</name>
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
          </runtime>
          <description>
            Allow unicode characters in URLs encoded as %u.
            This is an IIS extension to HTTP, UNICODE (UTF-7, UTF-8 etc.) URLs
            are forbidden by the RFC as default.
          </description>
        </attribute>
        <attribute>
          <name>permit_invalid_hex_escape</name>
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
          </runtime>
          <description>
             Allow invalid hexadecimal escaping in URLs (% must be followed by two hexadecimal digits).
          </description>
        </attribute>
        <attribute>
          <name>permit_http09_responses</name>
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
            Allow server responses to use the limited HTTP/0.9 protocol.
            As these responses carry no control information, verifying
            the validity of the protocol stream is impossible. This does not
            pose a threat to web clients, but exploits might pass undetected
            if this option is enabled for servers. It is recommended to turn this
            option off for protecting servers and only enable it when
            Zorp is used in front of users.
          </description>
        </attribute>
        <attribute>
          <name>keep_persistent</name>
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
          </runtime>
          <description>
            Try to keep the connection to the client persistent even if
            the server does not support it.
          </description>
        </attribute>
        <attribute>
          <name>connection_mode</name>
          <type>
            <link id="enum.http.connection"/>
          </type>
          <conftime/>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            This value reflects the state of the session. If the value
            equals to 'HTTP_CONNECTION_CLOSE', the session will be
            closed after serving the current request. Otherwise, if the
            value is 'HTTP_CONNECTION_KEEPALIVE' another request will be
            fetched from the client. This attribute can be used to
            forcibly close a keep-alive connection.
          </description>
        </attribute>
        <attribute>
          <name>parent_proxy</name>
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
            <write/>
          </runtime>
          <description>
            The address or hostname of the parent proxy to be connected.
            Either DirectedRouter or InbandRouter has to be used when using parent proxy.
          </description>
        </attribute>
        <attribute>
          <name>parent_proxy_port</name>
          <type>
            <integer/>
          </type>
          <default>3128</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            The port of the parent proxy to be connected.
          </description>
        </attribute>
        <attribute>
          <name>default_port</name>
          <type>
            <integer/>
          </type>
          <default>80</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            This value is used in non-transparent mode when the
            requested URL does not contain a port number. The default
            should be 80, otherwise the proxy may not function
            properly.
          </description>
        </attribute>
        <attribute>
          <name>use_default_port_in_transparent_mode</name>
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
            Set the target port to the value of <parameter>default_port</parameter> in transparent mode. This ensures that only the ports specified in <parameter>target_port_range</parameter> can
            be used by the clients, even if InbandRouter is used.
          </description>
        </attribute>
        <attribute>
          <name>use_canonicalized_urls</name>
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
            This attribute enables URL canonicalization, which means to
            automatically convert URLs to their canonical form. This
            enhances security but might cause interoperability problems
            with some applications. It is recommended to disable this
            setting on a per-destination basis. URL filtering still sees
            the canonicalized URL, but at the end the proxy sends the
            original URL to the server.
          </description>
        </attribute>
        <attribute>
          <name>rewrite_host_header</name>
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
            Rewrite the Host header in requests when URL redirection is
            performed.
          </description>
        </attribute>
        <attribute>
          <name>reset_on_close</name>
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
            Whenever the connection is terminated without a proxy
            generated error message, send an RST instead of a normal
            close. Causes some clients to automatically reconnect.
          </description>
        </attribute>
        <attribute>
          <name>require_host_header</name>
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
            Require the presence of the Host header. If set to FALSE,
            the real URL cannot be recovered from certain requests, which
            might cause problems with URL filtering.
          </description>
        </attribute>
        <attribute>
          <name>strict_header_checking</name>
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
          </runtime>
          <description>
            Require RFC conformant HTTP headers.
          </description>
        </attribute>
        <attribute>
          <name>strict_header_checking_action</name>
          <type>
            <link id="action.http.hdr"/>
          </type>
          <default>HTTP_HDR_DROP</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
          </runtime>
          <description>
            This attribute control what will the Zorp do if a non-rfc conform
            or unknown header found in the communication. Only the HTTP_HDR_ACCEPT,
            HTTP_HDR_DROP and HTTP_HDR_ABORT can be used.
          </description>
        </attribute>
        <attribute>
          <name>permit_null_response</name>
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
            Permit RFC incompliant responses with headers not terminated
            by CRLF and not containing entity body.
          </description>
        </attribute>
        <attribute>
          <name>max_hostname_length</name>
          <type>
            <integer/>
          </type>
          <default>256</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            Maximum allowed length of the hostname field in URLs.
          </description>
        </attribute>
        <attribute>
          <name>max_line_length</name>
          <type>
            <integer/>
          </type>
          <default>4096</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
          </runtime>
          <description>
             Maximum allowed length of lines in requests and responses. This
             value does not affect data transfer, as data is
             transmitted in binary mode.
          </description>
        </attribute>
        <attribute>
          <name>max_url_length</name>
          <type>
            <integer/>
          </type>
          <default>4096</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            Maximum allowed length of an URL in a request. Note that this
            directly affects forms using the 'GET' method to pass data
            to CGI scripts.
          </description>
        </attribute>
        <attribute>
          <name>max_body_length</name>
          <type>
            <integer/>
          </type>
          <default>0</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            Maximum allowed length of an HTTP request or response body. The default "0" value means that the length of the body is not limited.
          </description>
        </attribute>
        <attribute>
          <name>max_chunk_length</name>
          <type>
            <integer/>
          </type>
          <default>0</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            Maximum allowed length of a single chunk when using chunked
            transfer-encoding. The default "0" value means that the length of the chunk is not limited.
          </description>
        </attribute>
        <attribute>
          <name>max_header_lines</name>
          <type>
            <integer/>
          </type>
          <default>50</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            Maximum number of header lines allowed in a request or response.
          </description>
        </attribute>
        <attribute>
          <name>max_keepalive_requests</name>
          <type>
            <integer/>
          </type>
          <default>0</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            Maximum number of requests allowed in a single session. If the number of
            requests in the session the reaches this limit,
            the connection is terminated. The default "0" value allows
            unlimited number of requests.
          </description>
        </attribute>
        <attribute>
          <name>request_count</name>
          <type>
            <integer/>
          </type>
          <default>0</default>
          <conftime/>
          <runtime>
            <read/>
          </runtime>
          <description>
            The number of keepalive requests within the session.
          </description>
        </attribute>
        <attribute>
          <name>timeout</name>
          <type>
            <integer/>
          </type>
          <default>300000</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            General I/O timeout in milliseconds. If there is no
            timeout specified for a given operation, this value is used.
          </description>
        </attribute>
        <attribute>
          <name>timeout_request</name>
          <type>
            <integer/>
          </type>
          <default>10000</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            Time to wait for a request to arrive from the client.
          </description>
        </attribute>
        <attribute>
          <name>timeout_response</name>
          <type>
            <integer/>
          </type>
          <default>300000</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>Time to wait for the HTTP status line to arrive from the server.</description>
        </attribute>
        <attribute>
          <name>rerequest_attempts</name>
          <type>
            <integer/>
          </type>
          <default>0</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>Controls the number of attempts the proxy takes
            to send the request to the server. In case of server failure, a
            reconnection is made and the complete request is repeated along
            with POST data.</description>
        </attribute>
        <attribute>
          <name>buffer_size</name>
          <type>
            <integer/>
          </type>
          <default>1500</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
          </runtime>
          <description>
            Size of the I/O buffer used to transfer entity bodies.
          </description>
        </attribute>
        <attribute>
          <name>request</name>
          <type>
            <hash>
              <key>
                <string display_name="HTTP request type"/>
              </key>
              <value>
                <link id="action.http.req"/>
              </value>
            </hash>
          </type>
          <default>empty</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            Normative policy hash for HTTP requests
            indexed by the HTTP method (e.g.: "GET", "PUT" etc.).
            See also <xref linkend="http_policies"/>.
          </description>
        </attribute>
        <attribute>
          <name>request_header</name>
          <type>
            <hash>
              <key>
                <string display_name="HTTP header name"/>
              </key>
              <value>
                <link id="action.http.hdr"/>
              </value>
            </hash>
          </type>
          <default>empty</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            Normative policy hash for HTTP header requests
            indexed by the header names (e.g.:
            "Set-cookie"). See also <xref linkend="http_header_policies"/>.
          </description>
        </attribute>
        <attribute>
          <name>response</name>
          <type>
            <hash>
              <key>
                <tuple>
                  <string display_name="HTTP method"/>
                  <string display_name="HTTP response code"/>
                </tuple>
              </key>
              <value>
                <link id="action.http.rsp"/>
              </value>
            </hash>
          </type>
          <default>empty</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            Normative policy hash for HTTP responses
            indexed by the HTTP method and the response code
            (e.g.: "PWD", "209" etc.). See also <xref linkend="http_policies"/>.
          </description>
        </attribute>
        <attribute>
          <name>response_header</name>
          <type>
            <hash>
              <key>
                <string display_name="HTTP response header name"/>
              </key>
              <value>
                <link id="action.http.hdr"/>
              </value>
            </hash>
          </type>
          <default>empty</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            Normative policy hash for HTTP header responses
            indexed by the header names (e.g.:
            "Set-cookie"). See also <xref linkend="http_header_policies"/>.
          </description>
        </attribute>
        <attribute>
          <name>response_mime_type</name>
          <type>
            <string/>
          </type>
          <default>n/a</default>
          <conftime/>
          <runtime>
            <read/>
          </runtime>
          <description>
            The MIME type of the response entity. Its value is only
            defined when the response is processed.
          </description>
        </attribute>
        <attribute>
          <name>request_method</name>
          <type>
            <string/>
          </type>
          <default>n/a</default>
          <conftime/>
          <runtime>
            <read/>
          </runtime>
          <description>
            Request method (GET, POST, etc.) sent by the client.
          </description>
        </attribute>
        <attribute>
          <name>request_version</name>
          <type>
            <string/>
          </type>
          <default>n/a</default>
          <conftime/>
          <runtime>
            <read/>
          </runtime>
          <description>
            Request version (1.0, 1.1, etc.) used by the client.
          </description>
        </attribute>
        <attribute>
          <name>request_url_scheme</name>
          <type>
            <string/>
          </type>
          <default>n/a</default>
          <conftime/>
          <runtime>
            <read/>
          </runtime>
          <description>
            Protocol specifier of the URL (http://, ftp://, etc.).
          </description>
        </attribute>
        <attribute>
          <name>request_url</name>
          <type>
            <string/>
          </type>
          <default>n/a</default>
          <conftime/>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            The URL requested by the client. It can be modified to redirect
            the current request.
          </description>
        </attribute>
        <attribute>
          <name>request_url_proto</name>
          <type>
            <string/>
          </type>
          <default>n/a</default>
          <conftime/>
          <runtime>
            <read/>
          </runtime>
          <description>
            Protocol specifier of the URL. This attribute is an alias for
            <parameter>request_url_scheme</parameter>.
          </description>
        </attribute>
        <attribute>
          <name>request_url_username</name>
          <type>
            <string/>
          </type>
          <default>n/a</default>
          <conftime/>
          <runtime>
            <read/>
          </runtime>
          <description>
            Username in the URL (if specified).
          </description>
        </attribute>
        <attribute>
          <name>request_url_passwd</name>
          <type>
            <string/>
          </type>
          <default>n/a</default>
          <conftime/>
          <runtime>
            <read/>
          </runtime>
          <description>
            Password in the URL (if specified).
          </description>
        </attribute>
        <attribute>
          <name>request_url_host</name>
          <type>
            <string/>
          </type>
          <default>n/a</default>
          <conftime/>
          <runtime>
            <read/>
          </runtime>
          <description>
            Remote hostname in the URL.
          </description>
        </attribute>
        <attribute>
          <name>request_url_port</name>
          <type>
            <integer/>
          </type>
          <default>n/a</default>
          <conftime/>
          <runtime>
            <read/>
          </runtime>
          <description>
            Port number as specified in the URL.
          </description>
        </attribute>
        <attribute>
          <name>request_url_file</name>
          <type>
            <string/>
          </type>
          <default>n/a</default>
          <conftime/>
          <runtime>
            <read/>
          </runtime>
          <description>
            Filename specified in the URL.
          </description>
        </attribute>
        <attribute>
          <name>request_mime_type</name>
          <type>
            <string/>
          </type>
          <default>n/a</default>
          <conftime/>
          <runtime>
            <read/>
          </runtime>
          <description>
            The MIME type of the request entity. Its value is only
            defined when the request is processed.
          </description>
        </attribute>
        <attribute>
          <name>current_header_name</name>
          <type>
            <string/>
          </type>
          <default>n/a</default>
          <conftime/>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            Name of the header. It is defined when the header is processed,
            and can be modified by the proxy to actually change a header in
            the request or response.
          </description>
        </attribute>
        <attribute>
          <name>current_header_value</name>
          <type>
            <string/>
          </type>
          <default>n/a</default>
          <conftime/>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            Value of the header. It is defined when the header is processed,
            and can be modified by the proxy to actually change the value of
            the header in the request or response.
          </description>
        </attribute>
        <attribute>
          <name>error_status</name>
          <type>
            <integer/>
          </type>
          <default>500</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            If an error occurs, Zorp uses this value as the status code
            of the HTTP response it generates.
          </description>
        </attribute>
        <attribute>
          <name>error_info</name>
          <type>
            <string/>
          </type>
          <default>n/a</default>
          <conftime/>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            A string to be included in error messages.
          </description>
        </attribute>
        <attribute>
          <name>error_msg</name>
          <type>
            <string/>
          </type>
          <default>n/a</default>
          <conftime/>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            A string used as an error message in the HTTP status line.
          </description>
        </attribute>
        <attribute>
          <name>error_headers</name>
          <type>
            <string/>
          </type>
          <default>n/a</default>
          <conftime/>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            A string included as a header in the error response.  The
            string must be a valid header and must end with a "\r\n"
            sequence.
          </description>
        </attribute>
        <attribute>
          <name>error_silent</name>
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
            Turns off verbose error reporting to the HTTP client (makes
            firewall fingerprinting more difficult).
          </description>
        </attribute>
        <attribute>
          <name>error_files_directory</name>
          <type>
            <string/>
          </type>
          <default>"/usr/share/zorp/http"</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            Location of HTTP error messages.
          </description>
        </attribute>
        <attribute>
          <name>auth_forward</name>
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
            Controls whether inband authentication information (username
            and password) should be forwarded to the upstream server.
            When a parent proxy is present, the incoming authentication
            request is put into a 'Proxy-Authorization' header. In other
            cases the 'WWW-Authorization' header is used.
          </description>
        </attribute>
        <attribute internal="yes">
          <name>auth_inband_supported</name>
          <type>
            <integer/>
          </type>
          <default>1</default>
          <conftime>
            <read/>
          </conftime>
          <runtime>
            <read/>
          </runtime>
          <description>
          </description>
        </attribute>
        <attribute internal="yes">
          <name>auth</name>
          <type>
            <FIXME_OBJECT/>
          </type>
          <default>n/a</default>
          <conftime>
            <write/>
          </conftime>
          <runtime>
            <read/>
          </runtime>
          <description>
          </description>
        </attribute>
        <attribute>
          <name>auth_realm</name>
          <type>
            <string/>
          </type>
          <default>"Zorp HTTP auth"</default>
          <conftime>
            <write/>
          </conftime>
          <runtime>
            <read/>
          </runtime>
          <description>
            The name of the authentication realm to be presented to
            the user in the dialog window during inband authentication.
          </description>
        </attribute>
        <attribute>
          <name>target_port_range</name>
          <type>
            <string/>
          </type>
          <default>"80,443"</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            List of ports that non-transparent requests are allowed to
            use. The default is to allow port 80 and 443 to permit HTTP
            and HTTPS traffic. (The latter also requires the
            CONNECT method to be enabled).
          </description>
        </attribute>
        <attribute>
          <name>request_stack</name>
          <type>
            <hash>
              <key>
                <string/>
              </key>
              <value>
                <link id="action.http.stk"/>
              </value>
            </hash>
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
            Attribute containing the request stacking policy: the
            hash is indexed based on method names (e.g.: GET). See <xref linkend="http_stacking"/>.
          </description>
        </attribute>
        <attribute>
          <name>response_stack</name>
          <type>
            <hash>
              <key>
                <string/>
              </key>
              <value>
                <link id="action.http.stk"/>
              </value>
            </hash>
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
            Attribute containing the response stacking policy: the
            hash is indexed based on method names (e.g.: GET). See <xref linkend="http_stacking"/>.
          </description>
        </attribute>
        <attribute>
          <name>connect_proxy</name>
          <type>
            <class filter="proxy"/>
          </type>
          <default>PlugProxy</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            For CONNECT requests the HTTP proxy starts an independent
            proxy to control the internal protocol. The connect_proxy
            attribute specifies which proxy class is used for this
            purpose.
          </description>
        </attribute>
            <attribute>
          <name>max_auth_time</name>
          <type>
            <integer/>
          </type>
          <default>0</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            Request password authentication from the client, invalidating
            cached one-time-passwords. If the time specified (in seconds)
            in this attribute expires, Zorp requests a new authentication
            from the client browser even if it still has a password cached.
          </description>
        </attribute>
        <attribute>
          <name>auth_by_cookie</name>
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
          </runtime>
          <description>
            Authentication informations for one-time-password mode is organized
            by a cookie not the address of the client.
          </description>
        </attribute>
        <attribute>
          <name>auth_by_form</name>
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
          </runtime>
          <description>
            When enabled, and the client tries to access an URL that requires
            authentication, Zorp displays webpage where users can enter their
            authentication information. If the authentication is successful, the
            result is cached in a cookie.
          </description>
        </attribute>
        <attribute>
          <name>auth_cache_time</name>
          <type>
            <integer/>
          </type>
          <default>0</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
          </runtime>
          <description>
            Caching authentication information this amount of seconds.
          </description>
        </attribute>
        <attribute>
          <name>auth_cache_update</name>
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
          </runtime>
          <description>
            Update authentication cache by every connection.
          </description>
        </attribute>
        <attribute>
          <name>enable_url_filter</name>
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
          </runtime>
          <description>
            Enables URL filtering in HTTP requests.
            See <xref linkend="zorp_http_urlfiltering"/> for details.
          </description>
        </attribute>
        <attribute>
          <name>enable_url_filter_dns</name>
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
          </runtime>
          <description>
            Enables DNS- and reverse-DNS resolution to ensure that a domain or URL is correctly categorized even
            when it is listed in the database using its domain name, but the client tries to access it with its IP address (or vice-versa).
            See <xref linkend="zorp_http_urlfiltering"/> for details.
          </description>
        </attribute>
        <attribute>
          <name>url_category</name>
          <type>
            <hash>
              <key>
                <urlcategory display_name="Category identifier"/>
              </key>
              <value>
                <link id="action.http.url"/>
              </value>
            </hash>
          </type>
          <default>empty</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            Normative policy hash for category-based URL-filtering.
            The hash is indexed by the name of the category.
          </description>
        </attribute>
        <attribute>
          <name>url_filter_uncategorized_action</name>
          <type>
            <link id="action.http.url"/>
          </type>
          <default>HTTP_URL_ACCEPT</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
            <write/>
          </runtime>
          <description>
            <para>
              The action applied to uncategorized (unknown) URLs when URL filtering is used.
              By default, uncategorized URLs are accepted: <parameter>self.url_filter_uncategorized_action=(HTTP_URL_ACCEPT,)</parameter>.
              Note that if you set this option to <parameter>HTTP_URL_REJECT</parameter>,
              you must add every URL on your intranet to a category and set an <parameter>HTTP_URL_ACCEPT</parameter> rule to this category,
              otherwise your clients will not able to access your intranet sites.
              For details, see <xref linkend="zorp_http_urlfiltering_configuring"/>.
            </para>
          </description>
        </attribute>
        <attribute>
          <name>language</name>
          <type>
            <string/>
          </type>
          <default>"en"</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
          </runtime>
          <description>
            Specifies the language of the HTTP error pages displayed to the client. English (<parameter>en</parameter>) is the default. Other supported languages: <parameter>de</parameter> (German); <parameter>hu</parameter> (Hungarian).
          </description>
        </attribute>
        <attribute maturity="obsolete">
          <name>transparent_server_requests</name>
          <type/>
          <description>
            A deprecated alias of the permit_server_requests attribute.
          </description>
        </attribute>
        <attribute maturity="obsolete">
          <name>transparent_proxy_requests</name>
          <type/>
          <description>
            A deprecated alias of permit_proxy_requests.
          </description>
        </attribute>
        <attribute maturity="obsolete">
          <name>request_timeout</name>
          <type/>
          <description>
            A deprecated alias of timeout_request.
          </description>
        </attribute>
        <attribute maturity="obsolete">
          <name>request_headers</name>
          <type/>
          <description>
            A deprecated alias of request_header.
          </description>
        </attribute>
        <attribute maturity="obsolete">
          <name>response_headers</name>
          <type/>
          <description>
            A deprecated alias of response_header.
          </description>
        </attribute>
        <attribute maturity="obsolete">
          <name>error_response</name>
          <type/>
          <description>
            A deprecated alias of error_status.
          </description>
        </attribute>
      </attributes>
    </metainfo>
    </class>
    """
    name = "http"
    auth_inband_supported = TRUE

    def __init__(self, session):
        """<method internal="yes">
          <summary>Initializes a HttpProxy instance.</summary>
          <metainfo>
            <attributes>
              <attribute>
                <name>session</name>
                <type>SESSION instance</type>
                <description>
                  the session this instance participates in
                </description>
                </attribute>
            </attributes>
          </metainfo>
          <description>
            <para>
              Creates and initializes a HttpProxy instance.
            </para>
          </description>
        </method>
        """
        self.connect_proxy = PlugProxy
        self.request_stack = {}
        self.response_stack = {}
        Proxy.__init__(self, session)

    def requestStack(self, side):
        """<method internal="yes">
        </method>
        """
        if side == 0:
            hash = self.request_stack
        else:
            hash = self.response_stack

        self.transfer_from = side
        try:
            stack_proxy = hash[self.request_method]
        except KeyError:
            try:
                stack_proxy = hash["*"]
            except KeyError:
                return (HTTP_STK_NONE, None)

        if isinstance(stack_proxy, type(())):
            while True:
                stack_type = stack_proxy[0]
                if stack_type == HTTP_STK_NONE:
                    return (HTTP_STK_NONE, None)
                elif stack_type == HTTP_STK_POLICY:
                    # call function
                    stack_proxy = stack_proxy[1](side)
                else:
                    return stack_proxy
        else:
            return (HTTP_STK_NONE, None)

    def connectMethod(self):
        """<method internal="yes">
          <summary>
            Create a connect_proxy instance.
          </summary>
          <description>
            <!-- FIXME -->
          </description>
          <metainfo>
          </metainfo>
        </method>
        """

        return self.stackProxy(self.session.client_stream, self.session.server_stream, self.connect_proxy, None)

    def getRequestHeader(self, header):
        """<method internal="no">
          <summary>
            Function returning the value of a request header.
          </summary>
          <metainfo>
            <arguments>
              <argument>
                <name>header</name>
                <type>STRING</type>
                <description>
                  Name of the header to look up.
                </description>
              </argument>
            </arguments>
          </metainfo>
          <description>
            This function looks up and returns the value of a header
            associated with the current request.
          </description>
        </method>
        """
        return self.__headerManip(0, 0, header)

    def setRequestHeader(self, header, new_value):
        """<method internal="no">
          <summary>
            Function changing the value of a request header.
          </summary>
          <metainfo>
            <arguments>
              <argument>
                <name>header</name>
                <type>STRING</type>
                <description>
                  Name of the header to change.
                </description>
              </argument>
              <argument>
                <name>new_value</name>
                <type>STRING</type>
                <description>
                  Change the header to this value.
                </description>
              </argument>
            </arguments>
          </metainfo>
          <description>
            This function looks up and changes the value of a header
            associated with the current request.
          </description>
        </method>
        """
        return self.__headerManip(1, 0, header, new_value)

    def getResponseHeader(self, header):
        """<method internal="no">
          <summary>
            Function returning the value of a response header.
          </summary>
          <metainfo>
            <arguments>
              <argument>
                <name>header</name>
                <type>STRING</type>
                <description>
                  Name of the header to look up.
                </description>
              </argument>
            </arguments>
          </metainfo>
          <description>
            This function looks up and returns the value of a header
            associated with the current response.
          </description>
        </method>
        """
        return self.__headerManip(0, 1, header)

    def setResponseHeader(self, header, new_value):
        """<method internal="no">
          <summary>
            Function changing the value of a response header.
          </summary>
          <metainfo>
            <arguments>
              <argument>
                <name>header</name>
                <type>STRING</type>
                <description>
                  Name of the header to change.
                </description>
              </argument>
              <argument>
                <name>new_value</name>
                <type>STRING</type>
                <description>
                  Change the header to this value.
                </description>
              </argument>
            </arguments>
          </metainfo>
          <description>
            This function looks up and changes the value of a header
            associated with the current response.
          </description>
        </method>
        """
        return self.__headerManip(1, 1, header, new_value)


class HttpProxy(AbstractHttpProxy):

    """<class maturity="stable">
    <summary>
      Default HTTP proxy based on AbstractHttpProxy.
    </summary>
    <description>
      <para>
        HttpProxy is a default HTTP proxy based on AbstractHttpProxy. It
        is transparent, and enables the most commonly used HTTP
        methods: "GET", "POST" and "HEAD".
      </para>
    </description>
    <metainfo>
      <attributes/>
    </metainfo>
    </class>
    """

    def config(self):
        """<method internal="yes">
          <summary>
            Default config event handler.
          </summary>
          <description>
            <para>
              Enables the most common HTTP methods so we have a
              useful default configuration.
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """
        self.request["GET"] = (HTTP_REQ_ACCEPT,)
        self.request["POST"] = (HTTP_REQ_ACCEPT,)
        self.request["HEAD"] = (HTTP_REQ_ACCEPT,)

# we are transparent by default
HttpProxyTransparent = HttpProxy



class HttpProxyNonTransparent(HttpProxy):

    """<class maturity="stable">
      <summary>
        HTTP proxy based on HttpProxy, operating in non-transparent mode.
      </summary>
      <description>
        <para>
          HTTP proxy based on HttpProxy. This class is identical to
          <link linkend="python.Http.HttpProxy">HttpProxy</link>
          with the only difference being that it is non-transparent
          (<parameter>transparent_mode = FALSE</parameter>). Consequently,
          clients must be explicitly configured to connect to this proxy
          instead of the target server and issue proxy requests. On the server
          side this proxy connects transparently to the target server.
        </para>
        <para>
          For the correct operation the proxy must be able to set
          the server address on its own. This can be accomplished by using
          <link linkend="python.Router.InbandRouter">InbandRouter</link>.
        </para>
      </description>
      <metainfo>
        <attributes/>
      </metainfo>
    </class>
    """

    def config(self):
        """<method internal="yes">
        <summary>
        Config event handler
        </summary>
        <description><para>
        Sets self.transparent_mode to FALSE to indicate
        non-transparent mode.</para>
        </description>
        <metainfo>
                <arguments/>
        </metainfo>
        </method>
        """
        HttpProxy.config(self)
        self.transparent_mode = FALSE


class HttpProxyURIFilter(HttpProxy):

    """<class maturity="stable">
      <summary>
         HTTP proxy based on HttpProxy, with URI filtering capability.
      </summary>
      <description>
        <para>
          HTTP proxy based on HttpProxy, having URL
          filtering capability. The matcher attribute should be
          initialized to refer to a Matcher object. The initialization
          should be done in the class body as shown in the next example.
        </para>
        <example>
          <title>URL filtering HTTP proxy</title>
          <synopsis>class MyHttp(HttpProxyURIFilter):
    matcher = RegexpFileMatcher('/etc/zorp/blacklist.txt', \
                                    '/etc/zorp/whitelist.txt')</synopsis>
        </example>
      </description>
      <metainfo>
        <attributes>
          <attribute>
            <name>matcher</name>
            <type>
              <class filter="matcherpolicy" existing="yes"/>
            </type>
            <default>None</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>Matcher determining whether access to an URL is permitted or not.</description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """

    def config(self):
        """<method internal="yes">
        </method>
        """
        HttpProxy.config(self)
        self.request["GET"] = (HTTP_REQ_POLICY, self.checkURL)
        self.request["POST"] = (HTTP_REQ_POLICY, self.checkURL)
        self.request["HEAD"] = (HTTP_REQ_POLICY, self.checkURL)

    def __post_config__(self):
        """<method internal="yes">
        </method>
        """
        HttpProxy.__post_config__(self)

        if not hasattr(self, "matcher"):
            self.matcher = None
        else:
            self.matcher = getMatcher(self.matcher)

    def checkURL(self, method, url, version):
        """<method internal="yes">
        </method>
        """
        ## LOG ##
        # This is an accounting message that reports request details.
        ##
        proxyLog(self, HTTP_ACCOUNTING, 4, "Http accounting; request='%s %s %s'" % (method, url, version))
        if self.matcher:
            if self.matcher.checkMatch(url):
                ## LOG ##
                # This message indicates that the request was blocked by the URIFilter.
                ##
                proxyLog(self, HTTP_REQUEST, 6, "Request administratively prohibited; request='%s %s %s'" % (method, url, version))
                self.error_info = 'Accessing this content was administratively prohibited.'
                return HTTP_REQ_REJECT
        return HTTP_REQ_ACCEPT


class HttpProxyURIFilterNonTransparent(HttpProxyURIFilter):

    """<class maturity="stable">
      <summary>
        HTTP proxy based on HttpProxyURIFilter, with URI filtering capability and permitting non-transparent requests.
      </summary>
      <description>
        <para>
          HTTP proxy based on HttpProxyURIFilter, but operating in             non-transparent mode (<parameter>transparent_mode = FALSE</parameter>).
        </para>
      </description>
      <metainfo>
        <attributes/>
      </metainfo>
    </class>
    """

    def config(self):
        """<method internal="yes">
        </method>
        """
        HttpProxyURIFilter.config(self)
        self.transparent_mode = FALSE


class HttpWebdavProxy(HttpProxy):

    """<class maturity="stable">
      <summary>
        HTTP proxy based on HttpProxy, allowing WebDAV extensions.
      </summary>
      <description>
        <para>
          HTTP proxy based on HttpProxy, also capable of inspecting WebDAV extensions of the HTTP protocol.
        </para>
        <para>The following requests are permitted: PROPFIND; PROPPATCH; MKCOL; COPY; MOVE; LOCK; UNLOCK.
            </para>
      </description>
      <metainfo>
        <attributes/>
      </metainfo>
    </class>
    """

    def config(self):
        """<method internal="yes">
        </method>
        """
        HttpProxy.config(self)
        self.request["PROPFIND"] = (HTTP_REQ_ACCEPT)
        self.request["PROPPATCH"] = (HTTP_REQ_ACCEPT)
        self.request["MKCOL"] = (HTTP_REQ_ACCEPT)
        self.request["COPY"] = (HTTP_REQ_ACCEPT)
        self.request["MOVE"] = (HTTP_REQ_ACCEPT)
        self.request["LOCK"] = (HTTP_REQ_ACCEPT)
        self.request["UNLOCK"] = (HTTP_REQ_ACCEPT)


class NontransHttpWebdavProxy(HttpProxyNonTransparent):

    """<class maturity="stable">
      <summary>
        HTTP proxy based on HttpProxyNonTransparent, allowing WebDAV extension in non-transparent
        requests.
      </summary>
      <description>
        <para>
          HTTP proxy based on HttpProxyNonTransparent, operating in non-transparent mode (<parameter>transparent_mode = FALSE</parameter>) and capable of inspecting WebDAV extensions of the HTTP protocol.
        </para>
        <para>The following requests are permitted: PROPFIND; PROPPATCH; MKCOL; COPY; MOVE; LOCK; UNLOCK.
            </para>
      </description>
      <metainfo>
        <attributes/>
      </metainfo>
    </class>
    """

    def config(self):
        """<method internal="yes">
        </method>
        """
        HttpProxyNonTransparent.config(self)
        self.request["PROPFIND"] = (HTTP_REQ_ACCEPT)
        self.request["PROPPATCH"] = (HTTP_REQ_ACCEPT)
        self.request["MKCOL"] = (HTTP_REQ_ACCEPT)
        self.request["COPY"] = (HTTP_REQ_ACCEPT)
        self.request["MOVE"] = (HTTP_REQ_ACCEPT)
        self.request["LOCK"] = (HTTP_REQ_ACCEPT)
        self.request["UNLOCK"] = (HTTP_REQ_ACCEPT)




class HttpProxyURLCategoryFilter(HttpProxy):

    """
    <class maturity="stable">
      <summary>
        HTTP proxy based on HttpProxy, with URL filtering capability based on categories.
      </summary>
      <description>
        <para>
          HTTP proxy based on HttpProxy with enabled URL filtering (with DNS and reverse-DNS resolution)
          and preconfigured default category actions.
        </para>
        <para>
          The following categories have policy action <parameter>HTTP_URL_REJECT</parameter>:
        </para>
        <itemizedlist>
          <listitem><para>ads</para></listitem>
          <listitem><para>adult</para></listitem>
          <listitem><para>blacklist</para></listitem>
          <listitem><para>drugs</para></listitem>
          <listitem><para>gambling</para></listitem>
          <listitem><para>hacking</para></listitem>
          <listitem><para>phishing</para></listitem>
          <listitem><para>porn</para></listitem>
          <listitem><para>sexuality</para></listitem>
          <listitem><para>spyware</para></listitem>
          <listitem><para>violence</para></listitem>
          <listitem><para>virusinfected</para></listitem>
          <listitem><para>warez</para></listitem>
        </itemizedlist>
        <para>
          The following categories have policy action <parameter>HTTP_URL_ACCEPT</parameter>:
        </para>
        <itemizedlist>
          <listitem><para>whitelist</para></listitem>
        </itemizedlist>
      </description>
      <metainfo>
        <attributes/>
      </metainfo>
    </class>
    """

    def config(self):
        """
        <method internal="yes"/>
        """

        HttpProxy.config(self)

        self.enable_url_filter = TRUE
        self.enable_url_filter_dns = TRUE

        self.url_category['blacklist'] = HTTP_URL_REJECT
        self.url_category['whitelist'] = HTTP_URL_ACCEPT

        self.url_category['ads'] = HTTP_URL_REJECT
        self.url_category['adult'] = HTTP_URL_REJECT
        self.url_category['blacklist'] = HTTP_URL_REJECT
        self.url_category['drugs'] = HTTP_URL_REJECT
        self.url_category['gambling'] = HTTP_URL_REJECT
        self.url_category['hacking'] = HTTP_URL_REJECT
        self.url_category['phishing'] = HTTP_URL_REJECT
        self.url_category['porn'] = HTTP_URL_REJECT
        self.url_category['sexuality'] = HTTP_URL_REJECT
        self.url_category['spyware'] = HTTP_URL_REJECT
        self.url_category['violence'] = HTTP_URL_REJECT
        self.url_category['virusinfected'] = HTTP_URL_REJECT
        self.url_category['warez'] = HTTP_URL_REJECT
