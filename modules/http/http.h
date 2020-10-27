/***************************************************************************
 *
 * Copyright (c) 2000-2015 BalaBit IT Ltd, Budapest, Hungary
 * Copyright (c) 2015-2018 BalaSys IT Ltd, Budapest, Hungary
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 ***************************************************************************/

#ifndef ZORP_MODULES_HTTP_H_INCLUDED
#define ZORP_MODULES_HTTP_H_INCLUDED

#include <zorpll/string.h>

#include <zorp/zorp.h>
#include <zorp/proxy.h>
#include <zorp/proxystack.h>
#include <zorpll/streamline.h>
#include <zorp/authprovider.h>
#include <zorp/dimhash.h>
#include <zorpll/poll.h>
#include <zorp/attach.h>
#include <zorpll/blob.h>
#include <zorp/proxy/transfer2.h>
#include <zorp/policy.h>

#include <vector>
#include <utility> // pair

#include "httpcommon.h"

/* general limits applied to headers, etc. */
#define HTTP_MAX_LINE           32768
#define HTTP_MAX_URL            32768
#define HTTP_BLOCKSIZE		4096
#define HTTP_MAX_EMPTY_REQUESTS 3

/* error tags */
#define HTTP_DEBUG     "http.debug"
#define HTTP_INFO      "http.info"
#define HTTP_ERROR     "http.error"
#define HTTP_POLICY    "http.policy"
#define HTTP_REQUEST   "http.request"
#define HTTP_RESPONSE  "http.response"
#define HTTP_VIOLATION "http.violation"
#define HTTP_ACCOUNTING "http.accounting"

// URL filtering verdicts
// The order reflects the priority during the filtering decision.
// A REJECT verdict should always override a REDIRECT or an ACCEPT verdict
enum class HttpUrlVerdict
{
  REJECT = 1,
  REDIRECT,
  ACCEPT,
  FIRST = REJECT,
  LAST = ACCEPT
};

/* request specific constants */
typedef enum _HttpRequestVerdict
{
  HTTP_REQ_ACCEPT = 1,
  HTTP_REQ_DENY = 2,
  HTTP_REQ_REJECT = 3,
  HTTP_REQ_ABORT = 4,
  HTTP_REQ_POLICY = 6,
  HTTP_REQ_CUSTOM_RESPONSE = 7,
} HttpRequestVerdict;

/* response specific constants */
typedef enum _HttpResponseVerdict
{
  HTTP_RSP_ACCEPT = 1,
  HTTP_RSP_DENY = 2,
  HTTP_RSP_REJECT = 3,
  HTTP_RSP_ABORT = 4,
  HTTP_RSP_POLICY = 6,
} HttpResponseVerdict;

/* header specific constants */
#define HTTP_HDR_ACCEPT        1
#define HTTP_HDR_ABORT         4
#define HTTP_HDR_DROP          5
#define HTTP_HDR_POLICY        6
#define HTTP_HDR_CHANGE_NAME   100
#define HTTP_HDR_CHANGE_VALUE  101
#define HTTP_HDR_CHANGE_BOTH   102
#define HTTP_HDR_CHANGE_REGEXP 103
#define HTTP_HDR_INSERT        104
#define HTTP_HDR_REPLACE       105

#define HTTP_STK_NONE		1
#define HTTP_STK_DATA		2
#define HTTP_STK_MIME		3

/* connection mode */
#define HTTP_CONNECTION_CLOSE		0
#define HTTP_CONNECTION_KEEPALIVE	1
#define HTTP_CONNECTION_UNKNOWN		2

/* request type */
#define HTTP_REQTYPE_SERVER        0     /* simple server request */
#define HTTP_REQTYPE_PROXY         1     /* proxy request */

/* request protocol flags */
#define HTTP_REQ_FLG_HEAD       2
#define HTTP_REQ_FLG_ASTERIX    4
#define HTTP_REQ_FLG_CONNECT    8
#define HTTP_REQ_FLG_POST      16

/* response protocol flags */
#define HTTP_RESP_FLG_CONTINUE     1
#define HTTP_RESP_FLG_SUPPRESS     2
#define HTTP_RESP_FLG_DONTEXPECT   4
#define HTTP_RESP_FLG_STOP         8

/* HTTP header value flags */

/* format flags */
#define HTTP_HDR_FF_URL             (1 << 1)
#define HTTP_HDR_FF_ANY             (1 << 2)

/* character flags */
#define HTTP_HDR_CF_ALPHA           (1 << 3)
#define HTTP_HDR_CF_NUMERIC         (1 << 4)
#define HTTP_HDR_CF_SPACE           (1 << 5)
#define HTTP_HDR_CF_COMMA           (1 << 6)
#define HTTP_HDR_CF_DOT             (1 << 7)
#define HTTP_HDR_CF_BRACKET         (1 << 8)
#define HTTP_HDR_CF_EQUAL           (1 << 9)
#define HTTP_HDR_CF_DASH            (1 << 10)
#define HTTP_HDR_CF_SLASH           (1 << 11)
#define HTTP_HDR_CF_COLON           (1 << 12)
#define HTTP_HDR_CF_SEMICOLON       (1 << 13)
#define HTTP_HDR_CF_AT              (1 << 14)
#define HTTP_HDR_CF_UNDERLINE       (1 << 15)
#define HTTP_HDR_CF_AND             (1 << 16)
#define HTTP_HDR_CF_BACKSLASH       (1 << 17)
// *
#define HTTP_HDR_CF_ASTERIX         (1 << 19)
#define HTTP_HDR_CF_DOLLAR          (1 << 20)
// #
#define HTTP_HDR_CF_HASHMARK        (1 << 21)
#define HTTP_HDR_CF_PLUS            (1 << 22)
#define HTTP_HDR_CF_QUOTE           (1 << 23)
#define HTTP_HDR_CF_QUESTIONMARK    (1 << 24)
#define HTTP_HDR_CF_PERCENT         (1 << 25)
#define HTTP_HDR_CF_TILDE           (1 << 26)
#define HTTP_HDR_CF_EXCLAM          (1 << 27)

typedef enum _HttpMessageCode
{
  HTTP_MSG_NOT_ASSIGNED     = -1,
  HTTP_MSG_OK               =  0,
  HTTP_MSG_CLIENT_SYNTAX    =  1,
  HTTP_MSG_SERVER_SYNTAX    =  2,
  HTTP_MSG_POLICY_SYNTAX    =  3,
  HTTP_MSG_POLICY_VIOLATION =  4,
  HTTP_MSG_INVALID_URL      =  5,
  HTTP_MSG_CONNECT_ERROR    =  6,
  HTTP_MSG_IO_ERROR         =  7,
  HTTP_MSG_AUTH_REQUIRED    =  8,
  HTTP_MSG_CLIENT_TIMEOUT   =  9,
  HTTP_MSG_SERVER_TIMEOUT   = 10,
  HTTP_MSG_BAD_CONTENT      = 11,
  HTTP_MSG_FTP_ERROR        = 12,
  HTTP_MSG_REDIRECT         = 13,
  HTTP_MSG_INTERNAL         = 14
} HttpMessageCode;

/* protocol to pull data on the server side */
#define HTTP_PROTO_HTTP		0
#define HTTP_PROTO_HTTPS	1
#define HTTP_PROTO_FTP		2

/* special HTTP lengths, values >= 0 are the exact length of the chunk */
#define HTTP_LENGTH_NONE		-2
#define HTTP_LENGTH_UNKNOWN		-1

#define HTTP_TRANSFER_NORMAL             0
#define HTTP_TRANSFER_TO_BLOB            1
#define HTTP_TRANSFER_FROM_BLOB          2

typedef struct _HttpHeader HttpHeader;
typedef struct _HttpHeaders HttpHeaders;
typedef struct _HttpURL HttpURL;

using CookiePairVector = std::vector<std::pair<std::string, std::string>>;

/* this structure represents an HTTP header, it can easily be added to our
 * header structure without having to also include it in the protocol when
 * reconstructing the list of headers by using the 'present' member field.
 * When present is TRUE the header will be sent to the peers, when it is
 * FALSE it will not.
 */

struct _HttpHeader
{
  GString *name;
  GString *value;
  gboolean present;
};

/* This structure represents a set of headers with possibility to quickly
 * look headers up (through a GHashTable indexed by the header name), and also
 * retain original order, using a linked list.
 */
struct _HttpHeaders
{
  /* linked list of HttpHeader structures */
  GList *list;

  /* hash table for quick lookups */
  GHashTable *hash;

  /* flattened representation of the headers */
  GString *flat;
};

struct _HttpURL
{
  /* this is the original form of the URL local part in case canonicalization was disabled */
  GString *original_local;
  /* all gstrings below might contain NUL characters as they store the URL-decoded form */
  GString *scheme;
  GString *user;
  GString *passwd;
  GString *host;
  guint port;
  GString *file;
  GString *query;
  GString *fragment;
  gboolean need_brackets; /* IPv6 addresses are surrounded by brackets, this information needs to be preserved for formatting */
};

typedef struct _HttpElementInfo
{
  const gchar *name;
  guint32 flags;
  gssize max_len; /* only used for headers */
} HttpElementInfo;

/* This structure represents an HTTP proxy */
struct _HttpProxy
{
  static const std::string zorp_realm_cookie_name;

  ZProxy super;

  /* poll is used during transfers */
  ZPoll *poll;

  /* stacked proxy */
  ZStackedProxy *stacked;

  /* general I/O timeout */
  guint timeout;

  /* timeout we wait for a request */
  guint timeout_request;

  /* timeout we wait for a response */
  guint timeout_response;

  guint rerequest_attempts;
  gboolean request_data_stored;
  ZBlob *request_data;

  /* request/response header-sets */
  HttpHeaders headers[EP_MAX];

  /* maximum number of headers in a single request/response */
  guint max_header_lines;

  /* these values can be used to change the actual header name/value while
   * iterating through the set of headers */
  GString *current_header_name, *current_header_value;

  /* borrowed reference to the request or response connection header
   * modifyable as long as the request/response headers are not
   * reconstructed */
  HttpHeader *connection_hdr;

  /* inband authentication provider */
  ZAuthProvider *auth;

  /* dummy, exported variable to indicate that we are able to deal with inband authentication */
  gboolean auth_inband_supported;

  /* whether to forward authentication requests */
  gboolean auth_forward;

  /* authentication realm to show to our clients */
  GString *auth_realm;

  /* the value in the authentication header, used when forwarding
   * credentials (see auth_forward) */
  GString *auth_header_value;

  /* cached authentication value, we do not authenticate persistent
   * requests, provided they have the same authentication header */
  GString *old_auth_header;

  /* request method, like GET or POST */
  GString *request_method;

  /* request flags (one of HTTP_REQ_FLG_*)  */
  guint request_flags;

  /* request url as sent by the client */
  GString *request_url;
  HttpURL request_url_parts;

  /* HTTP version as presented in the client request */
  gchar request_version[16];

  /* proxy or server type request was received, HTTP_REQ_PROXY or HTTP_REQ_SERVER */
  guint request_type;

  /* the protocol used to retrieve data HTTP/FTP */
  guint server_protocol;

  /* port range permitted in non-transparent mode */
  GString *target_port_range;

  /* server we are connected to, a new connection is established once this
   * changes */
  GString *connected_server;

  /* port we are connected to */
  guint connected_port;

  /* the target server as derived from the request (URL and Host header) */
  GString *remote_server;

  /* the target port as dervied from the request */
  guint remote_port;

  gboolean use_default_port_in_transparent_mode;

  /* whether to use canonicalized URLs by default */
  gboolean use_canonicalized_urls;

  /* specifies the default HTTP port, which is used when the port is not
   * specified in the URL */
  guint default_http_port;

  /* specifies the default HTTPS port, which is used when the port is not
   * specified in the URL */
  guint default_https_port;

  /* specifies the default FTP port, which is used when the port is not
   * specified in the URL */
  guint default_ftp_port;

  /* HTTP version as presented in the server's response */
  gchar response_version[16];

  /* response status code, represented by 3 digits and a trailing NUL character */
  gchar response[4];

  /* response flags, HTTP_RESP_FLG_* */
  guint response_flags;

  /* parsed representation of response */
  gint response_code;

  /* response message at the tail of the HTTP status line */
  GString *response_msg;

  /* client connection persistency, one of HTTP_CONNECTION_* */
  guint connection_mode;
  guint server_connection_mode;
  gboolean keep_persistent;

  /* whether we are transparent, e.g. leave request type intact */
  gboolean transparent_mode;

  /* whether to allow incoming server requests */
  gboolean permit_server_requests;

  /* whether to allow incoming proxy requests */
  gboolean permit_proxy_requests;

  /* whether to allow %uXXXX encoding in URLs */
  gboolean permit_unicode_url;

  /* whether to care about hexadecimal encoded characters validity */
  gboolean permit_invalid_hex_escape;

  /* whether to permit HTTP/0.9 responses at all */
  gboolean permit_http09_responses;

  /* whether to permit FTP requests over non-transparent HTTP */
  gboolean permit_ftp_over_http;

  /* FTP over HTTP variables */
  ZAttach *ftp_data_attach;

  /* address, or hostname of the parent proxy, if empty direct connection is used */
  GString *parent_proxy;

  /* port of the parent proxy */
  guint parent_proxy_port;

  /* rewrite host header when redirection is done */
  gboolean rewrite_host_header;
  gboolean reset_on_close;

  /* require the existance of the Host: header */
  gboolean require_host_header;

  /* permit responses with no terminating CRLF and data */
  gboolean permit_null_response;

  /* 0: accept rfc incompliant headers, 1: require rfc compliance */
  gboolean strict_header_checking;
  guint strict_header_checking_action;

  /* parsed protocol version: 0x major minor (0x0009 0x0100 0x0101) */
  guint proto_version[EP_MAX];

  /* user tunable protocol limits */
  guint max_line_length;
  guint max_hostname_length;
  guint max_url_length;
  guint max_keepalive_requests;
  guint max_body_length;
  guint max_chunk_length;

  /* number of requests so far */
  guint request_count;

  /* policy hash to process on request methods */
  GHashTable *request_method_policy;

  /* policy hash to process on request headers */
  GHashTable *request_header_policy;

  /* policy hash to process on response codes */
  ZDimHashTable *response_policy;

  /* policy hash to process on response headers */
  GHashTable *response_header_policy;

  /* hack: when transfer feels the connection to the server should be
   * reestablished, it sets this value to TRUE */

  gboolean reattempt_connection;
  gboolean force_reconnect;

  /* transfer object */
  HttpTransfer *transfer;

  /* buffer size used while copying the blobs */
  guint buffer_size;

  /* information used when generating the built in error pages */

  /* internal error codes, HTTP_MSG_* */
  gint error_code;

  /* status code to send to the client (e.g. 500 */
  guint error_status;

  /* whether to generate error pages at all, or simply return an empty page */
  gboolean error_silent;

  /* additional information to be shown to the client (included in the error pages as @INFO@) */
  GString *error_info;

  /* error message sent on the HTTP status line */
  GString *error_msg;

  /* headers sent together with the error page */
  GString *error_headers;

  /* the directory where error file templates are stored */
  GString *error_files_directory;

  /* send a locally constructed reponse immediately to client without the server being involved */
  gboolean send_custom_response;

  /* body to send to client as an immediate response */
  GString *custom_response_body;

  /* Maximum allowed time between two forced authentication request */
  gint max_auth_time;

  /* Enable authentication cache based on Cookies. */
  gboolean auth_by_cookie;

  /* Enable authentication based on html form (captive portal). */
  gboolean auth_by_form;
  GString *login_page_path;

  /* Do not authenticate this amount of sec. */
  gint auth_cache_time;

  /* Update the auth cache stamp at each request */
  gboolean auth_cache_update;

  /* Enable the radix-tree based url filter/classifier */
  gboolean enable_url_filter;

  /* Do additional IP->domain and domain->IP lookups for url classification */
  gboolean enable_url_filter_dns;

  /* Default verdict for URL filter if no matching categories were found */
  ZPolicyObj *url_filter_uncategorized_action;

  /* policy hash to process on url categories */
  GHashTable *url_category;

  /* Categories the request falls into */
  ZPolicyObj *request_categories;

  GString *append_cookie;
};

extern ZClass HttpProxy__class;

typedef guint (*HttpHeaderFilter)(HttpProxy *self, GString *header_name, GString *header_value);

GIOStatus http_write(HttpProxy *self, guint side, gchar *buf, size_t buflen);
gboolean http_connect_server(HttpProxy *self);

gboolean http_data_transfer(HttpProxy *self, gint transfer_type, ZEndpoint from, ZStream *from_stream, ZEndpoint to, ZStream *to_stream, gboolean expect_data, gboolean suppress_data, HttpTransferPreambleFunc format_preamble);

gboolean
http_lookup_header(HttpHeaders *headers, const gchar *what, HttpHeader **p);

CookiePairVector::iterator
http_find_cookie_by_name(CookiePairVector &cookie_vector, const std::string &cookie_name);

CookiePairVector http_parse_header_cookie(HttpHeaders *hdrs);

void
http_write_header_cookie(HttpHeaders *hdrs, const CookiePairVector &cookie_hash);

gboolean
http_fetch_headers(HttpProxy *self, ZEndpoint side);

gboolean
http_filter_headers(HttpProxy *self, ZEndpoint side, HttpHeaderFilter filter);

gboolean
http_flat_headers(HttpHeaders *hdrs);

gboolean
http_flat_headers_into(HttpHeaders *hdrs, GString *into);

void
http_clear_headers(HttpHeaders *hdrs);

void
http_init_headers(HttpHeaders *hdrs);

void
http_destroy_headers(HttpHeaders *hdrs);

HttpHeader *
http_add_header(HttpHeaders *hdrs, const gchar *name, gint name_len, const gchar *value, gint value_len);

void
http_log_headers(HttpProxy *self, ZEndpoint side, const gchar *tag);

gint http_filter_hash_compare(gconstpointer a, gconstpointer b);
gint http_filter_hash_bucket(gconstpointer a);

/* URL processing */

gboolean http_parse_url(HttpURL *url, gboolean permit_unicode_url, gboolean permit_invalid_hex_escape,
                        gboolean permit_relative_url, const gchar *url_str, const gchar **reason);
gboolean http_format_url(HttpURL *url, GString *encode_buf, gboolean format_absolute, gboolean permit_unicode_url,
                         gboolean canonicalized, const gchar **reason);
void http_init_url(HttpURL *url);
void http_destroy_url(HttpURL *url);

gboolean http_string_assign_url_decode(GString *part, gboolean permit_invalid_hex_escape,
                                       const gchar *src, gint len, const gchar **reason);
gboolean http_string_assign_form_url_decode(GString *part, gboolean permit_invalid_hex_escape,
                                            const gchar *src, gint len, const gchar **reason);

/* request/response processing */

gboolean
http_split_request(HttpProxy *self, gchar *line, gint length);
gboolean
http_split_response(HttpProxy *self, gchar *line, gint line_length);
gboolean
http_parse_version(HttpProxy *self, gint side, gchar *version_str);

gboolean
http_handle_ftp_request(HttpProxy *self);

void http_proto_init(void);

bool
http_query_string_get_value(const std::string &stream_line, const std::string &key, std::string &value);

/* inline functions */

extern GHashTable *request_proto_hash;
extern GHashTable *response_proto_hash;
extern GHashTable *request_hdr_proto_hash;
extern GHashTable *response_hdr_proto_hash;

static inline guint
http_proto_lookup_hash(GHashTable *hash, const gchar *index)
{
  HttpElementInfo *e;

  e = static_cast<HttpElementInfo *>(g_hash_table_lookup(hash, index));
  if (e)
    return e->flags;
  return 0;
}

static inline guint
http_proto_request_lookup(const gchar *req)
{
  return http_proto_lookup_hash(request_proto_hash, req);
}

static inline guint
http_proto_response_lookup(const gchar *resp)
{
  return http_proto_lookup_hash(response_proto_hash, resp);
}

static inline HttpElementInfo *
http_proto_request_hdr_lookup(const gchar *req)
{
  return static_cast<HttpElementInfo *>(g_hash_table_lookup(request_hdr_proto_hash, req));
}

static inline HttpElementInfo *
http_proto_response_hdr_lookup(const gchar *resp)
{
  return static_cast<HttpElementInfo *>(g_hash_table_lookup(response_hdr_proto_hash, resp));
}
#endif
