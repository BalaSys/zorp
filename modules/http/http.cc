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
 *   Slightly based on the code by: Viktor Peter Kovacs <vps__@freemail.hu>
 *
 ***************************************************************************/

#include "http.h"

#include <zorpll/thread.h>
#include <zorpll/registry.h>
#include <zorpll/log.h>
#include <zorp/policy.h>
#include <zorp/authprovider.h>
#include <zorpll/misc.h>
#include <zorp/policy.h>
#include <zorpll/code_base64.h>
#include <zorpll/streamblob.h>
#include <zorpll/streamline.h>
#include <zorpll/random.h>
#include <zorpll/code.h>
#include <zorpll/code_base64.h>

#include <zorp/proxy/errorloader.h>

#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>

#include <memory>
#include <functional>
#include <algorithm>

#include "httpurlfilter.h"

static GHashTable *auth_hash = NULL;
G_LOCK_DEFINE_STATIC(auth_mutex);

const std::string HttpProxy::zorp_realm_cookie_name("ZorpRealm");

typedef struct _ZorpAuthInfo
{
  time_t last_auth_time;
  time_t accept_credit_until;
  time_t created_at;
  gchar *username;
  gchar **groups;
  gchar *basic_auth_creds;
} ZorpAuthInfo;

/**
 * http_filter_hash_compare:
 * @a: first item
 * @b: second item
 *
 * This function is the hash compare function for request header hashes.
 **/
gint
http_filter_hash_compare(gconstpointer a, gconstpointer b)
{
  z_enter();

  if (strcasecmp((char *) a, (char *) b) == 0)
    z_return(1);

  z_return(0);
}

/**
 * http_filter_hash_bucket:
 * @a: item to calculate hash value for
 *
 * This function is the hash calculation function for request header hashes.
 **/
gint
http_filter_hash_bucket(gconstpointer a)
{
  int sum = 0;
  char *s = (char *) a;

  z_enter();

  while (*s != 0)
    {
      sum += toupper(*s);
      s++;
    }

  z_return(sum % 16);
}

/**
 * http_config_set_defaults:
 * @self: HttpProxy instance
 *
 * This function initializes various attributes exported to the Python layer
 * for possible modification.
 **/
static void
http_config_set_defaults(HttpProxy *self)
{
  z_proxy_enter(self);
  self->connection_mode = HTTP_CONNECTION_CLOSE;
  self->server_connection_mode = HTTP_CONNECTION_CLOSE;
  self->force_reconnect = FALSE;
  self->transparent_mode = TRUE;
  self->permit_server_requests = TRUE;
  self->permit_proxy_requests = FALSE;
  self->permit_unicode_url = FALSE;
  self->permit_http09_responses = TRUE;

  self->rewrite_host_header = TRUE;
  self->require_host_header = TRUE;
  self->strict_header_checking = FALSE;
  self->strict_header_checking_action = ZV_DROP;
  self->permit_null_response = TRUE;
  self->max_line_length = 4096;
  self->max_url_length = 4096;
  self->max_header_lines = 50;
  self->max_hostname_length = 256;
  self->max_chunk_length = 0;
  self->timeout_request = 10000;
  self->timeout_response = 300000;
  self->timeout = 300000;
  self->default_http_port = 80;
  self->default_https_port = 443;
  self->default_ftp_port = 21;
  self->use_default_port_in_transparent_mode = TRUE;
  self->use_canonicalized_urls = TRUE;
  self->max_body_length = 0;
  self->buffer_size = 1500;
  self->rerequest_attempts = 0;

  http_init_headers(&self->headers[EP_CLIENT]);
  http_init_headers(&self->headers[EP_SERVER]);

  http_init_url(&self->request_url_parts);
  self->request_url = g_string_sized_new(128);

  self->current_header_name = g_string_sized_new(16);
  self->current_header_value = g_string_sized_new(32);

  self->parent_proxy = g_string_sized_new(0);
  self->parent_proxy_port = 3128;

  self->target_port_range = g_string_new("80,443");
  self->auth_header_value = g_string_sized_new(32);

  self->remote_server = g_string_sized_new(32);
  self->connected_server = g_string_sized_new(32);
  self->request_method = g_string_sized_new(16);
  self->response_msg = g_string_sized_new(32);

  self->request_method_policy =
    g_hash_table_new((GHashFunc) http_filter_hash_bucket,
                     (GCompareFunc) http_filter_hash_compare);
  self->request_header_policy =
    g_hash_table_new((GHashFunc) http_filter_hash_bucket,
                     (GCompareFunc) http_filter_hash_compare);

  self->response_policy =
    z_dim_hash_table_new(1, 2, DIMHASH_WILDCARD, DIMHASH_CONSUME);
  self->response_header_policy =
    g_hash_table_new((GHashFunc) http_filter_hash_bucket,
                     (GCompareFunc) http_filter_hash_compare);

  self->error_info = g_string_sized_new(0);
  self->error_msg = g_string_sized_new(0);
  self->error_headers = g_string_sized_new(0);
  self->error_code = HTTP_MSG_NOT_ASSIGNED;
  self->error_status = 500;
  self->error_files_directory = g_string_sized_new(0);

  self->error_silent = FALSE;

  self->send_custom_response = FALSE;
  self->custom_response_body = g_string_sized_new(0);

  self->max_auth_time = 0;

  self->auth_realm = g_string_new("Zorp HTTP auth");
  self->old_auth_header = g_string_sized_new(0);
  self->auth_by_cookie = FALSE;
  self->auth_by_form = FALSE;
  self->login_page_path = g_string_sized_new(0);

  self->enable_url_filter = FALSE;
  self->enable_url_filter_dns = FALSE;

  z_policy_lock(self->super.thread);
  self->url_filter_uncategorized_action = z_policy_var_build("(I)", HttpUrlVerdict::ACCEPT);
  z_policy_unlock(self->super.thread);

  self->url_category = g_hash_table_new(g_str_hash, g_str_equal);

  self->request_categories = NULL;

  z_proxy_return(self);
}

/**
 * http_config_init:
 * @self: HttpProxy instance
 *
 * This function is called right after the config() method to initialize
 * settings the Python layer specified for us.
 **/
static void
http_config_init(HttpProxy *self)
{
  z_proxy_enter(self);

  if (self->max_line_length > HTTP_MAX_LINE)
    self->max_line_length = HTTP_MAX_LINE;

  self->super.endpoints[EP_CLIENT]->timeout = self->timeout_request;
  self->poll = z_poll_new();
  z_proxy_return(self);
}

/**
 * http_query_request_version:
 * @self: HttpProxy instance
 * @name: name of requested variable
 * @value: unused
 *
 * This function is registered as a Z_VAR_TYPE_CUSTOM get handler, e.g. it
 * is called whenever one of the request_version attribute is requested from
 * Python. Instead of presetting that attribute before calling into Python
 * we calculate its value dynamically.
 **/
static ZPolicyObj *
http_query_request_version(HttpProxy *self, gchar *name, gpointer  /* value */)
{
  ZPolicyObj *res = NULL;

  z_proxy_enter(self);

  if (strcmp(name, "request_version") == 0)
    res = z_policy_var_build("s#", self->request_version, strlen(self->request_version));

  z_proxy_return(self, res);
}

/**
 * http_query_request_url:
 * @self: HttpProxy instance
 * @name: name of requested variable
 * @value: unused
 *
 * This function is registered as a Z_VAR_TYPE_CUSTOM get handler, e.g. it
 * is called whenever one of the request_url_* attributes are requested from
 * Python. Instead of presetting those attributes before calling into Python
 * we calculate their value dynamically.
 **/
static ZPolicyObj *
http_query_request_url(HttpProxy *self, gchar *name, gpointer  /* value */)
{
  ZPolicyObj *res = NULL;

  z_proxy_enter(self);

  if (strcmp(name, "request_url") == 0)
    res = z_policy_var_build("s#", self->request_url->str, self->request_url->len);
  else if (strcmp(name, "request_url_proto") == 0 || strcmp(name, "request_url_scheme") == 0)
    res = z_policy_var_build("s#", self->request_url_parts.scheme->str, self->request_url_parts.scheme->len);
  else if (strcmp(name, "request_url_username") == 0)
    res = z_policy_var_build("s#", self->request_url_parts.user->str, self->request_url_parts.user->len);
  else if (strcmp(name, "request_url_passwd") == 0)
    res = z_policy_var_build("s#", self->request_url_parts.passwd->str, self->request_url_parts.passwd->len);
  else if (strcmp(name, "request_url_host") == 0)
    res = z_policy_var_build("s#", self->request_url_parts.host->str, self->request_url_parts.host->len);
  else if (strcmp(name, "request_url_port") == 0)
    res = z_policy_var_build("i", self->request_url_parts.port ? self->request_url_parts.port : self->default_http_port);
  else if (strcmp(name, "request_url_file") == 0)
    res = z_policy_var_build("s#", self->request_url_parts.file->str, self->request_url_parts.file->len);
  else if (strcmp(name, "request_url_query") == 0)
    res = z_policy_var_build("s#", self->request_url_parts.query->str, self->request_url_parts.query->len);
  else
    PyErr_SetString(PyExc_AttributeError, "Unknown attribute");

  z_proxy_return(self, res);
}

/**
 * http_set_request_url:
 * @self: HttpProxy instance
 * @name: name of requested variable
 * @value: unused
 * @new: new value for attribute
 *
 * This function is registered as a Z_VAR_TYPE_CUSTOM set handler, e.g. it
 * is called whenever the request_url attribute are changed from Python.
 * We need to reparse the URL in these cases.
 **/
static gint
http_set_request_url(HttpProxy *self, gchar *name, gpointer  /* value */, PyObject *new_)
{
  z_proxy_enter(self);

  if (strcmp(name, "request_url") == 0)
    {
      gchar *str;
      const gchar *reason;

      if (!PyArg_Parse(new_, "s", &str))
        z_proxy_return(self, -1);

      if (!http_parse_url(&self->request_url_parts, self->permit_unicode_url,
                          self->permit_invalid_hex_escape, FALSE, str, &reason))
        {
          z_proxy_log(self, HTTP_ERROR, 2, "Policy tried to force an invalid URL; url='%s', reason='%s'", str, reason);
          z_policy_raise_exception_obj(z_policy_exc_value_error, "Invalid URL.");
          z_proxy_return(self, -1);
        }

      if (!http_format_url(&self->request_url_parts, self->request_url, TRUE, self->permit_unicode_url, TRUE, &reason))
        {
          z_proxy_log(self, HTTP_ERROR, 2, "Error canonicalizing URL; url='%s', reason='%s'", str, reason);
          z_policy_raise_exception_obj(z_policy_exc_value_error, "Invalid URL.");
          z_proxy_return(self, -1);
        }

      z_proxy_return(self, 0);
    }

  z_policy_raise_exception_obj(z_policy_exc_attribute_error, "Can only set request_url");
  z_proxy_return(self, -1);
}

/**
 * http_query_mime_type:
 * @self: HttpProxy instance
 * @name: name of requested variable
 * @value: unused
 *
 * This function is registered as a Z_VAR_TYPE_CUSTOM get handler, e.g. it
 * is called whenever one of the request_mime_type or response_mime_type
 * attributes are requested from Python. Instead of presetting those
 * attributes before calling into Python we calculate their value
 * dynamically.
 **/
static ZPolicyObj *
http_query_mime_type(HttpProxy *self, gchar *name, gpointer  /* value */)
{
  ZPolicyObj *res = NULL;
  HttpHeader *hdr;
  gboolean success;

  z_proxy_enter(self);

  if (strcmp(name, "request_mime_type") == 0)
    {
      success = http_lookup_header(&self->headers[EP_CLIENT], "Content-Type", &hdr);
    }
  else if (strcmp(name, "response_mime_type") == 0)
    {
      success = http_lookup_header(&self->headers[EP_SERVER], "Content-Type", &hdr);
    }
  else
    {
      PyErr_SetString(PyExc_AttributeError, "Unknown attribute");
      z_proxy_return(self, NULL);
    }

  if (!success || !hdr)
    {
      res = PyString_FromString("");
    }
  else
    {
      gchar *start, *end;

      start = hdr->value->str;

      while (*start == ' ')
        start++;

      end = strchr(hdr->value->str, ';');

      if (end)
        {
          end--;

          while (end > start && *end == ' ')
            end--;
        }

      if (end)
        res = PyString_FromStringAndSize(hdr->value->str, (end - start + 1));
      else
        res = PyString_FromString(hdr->value->str);
    }

  z_proxy_return(self, res);
}

static ZPolicyObj *
http_policy_header_manip(HttpProxy *self, ZPolicyObj *args)
{
  gint action, side;
  gchar *header, *new_value = NULL;
  HttpHeader *p = NULL;
  ZPolicyObj *res = NULL;

  z_proxy_enter(self);

  if (!z_policy_var_parse_tuple(args, "iis|s", &action, &side, &header, &new_value))
    goto error;

  side &= 1;

  switch (action)
    {
    case 0:

      /* get */
      if (http_lookup_header(&self->headers[side], header, &p))
        {
          res = z_policy_var_build("s", p->value->str);
        }
      else
        {
          res = z_policy_none_ref();
        }

      break;

    case 1:

      /* set */
      if (!new_value)
        goto error_set_exc;

      if (!http_lookup_header(&self->headers[side], header, &p))
        p = http_add_header(&self->headers[side], header, strlen(header), new_value, strlen(new_value));

      g_string_assign(p->value, new_value);
      p->present = TRUE;
      res = z_policy_none_ref();
      break;

    default:
      goto error_set_exc;
    }

  z_proxy_return(self, res);

 error_set_exc:
  z_policy_raise_exception_obj(z_policy_exc_value_error, "Invalid arguments.");

 error:
  z_proxy_return(self, NULL);

}

static ZPolicyObj *
http_query_headers_flat(HttpProxy *self, gint side)
{
  ZPolicyObj *res = NULL;

  z_proxy_enter(self);

  side &= 1;
  res = z_policy_var_build("s#", self->headers[side].flat->str, strlen(self->headers[side].flat->str));

  z_proxy_return(self, res);
}

static ZPolicyObj *
http_query_request_headers_flat(HttpProxy *self, gchar * /* name */, gpointer  /* value */)
{
  return http_query_headers_flat(self, EP_CLIENT);
}

static ZPolicyObj *
http_query_response_headers_flat(HttpProxy *self, gchar * /* name */, gpointer  /* value */)
{
  return http_query_headers_flat(self, EP_SERVER);
}


/**
 * http_register_vars:
 * @self: HttpProxy instance
 *
 * This function is called upon startup to export Python attributes.
 **/
static void
http_register_vars(HttpProxy *self)
{
  z_proxy_enter(self);
  z_proxy_var_new(&self->super, "transparent_mode",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->transparent_mode);

  z_proxy_var_new(&self->super, "permit_server_requests",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->permit_server_requests);

  z_proxy_var_new(&self->super, "permit_null_response",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->permit_null_response);

  z_proxy_var_new(&self->super, "permit_proxy_requests",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->permit_proxy_requests);

  z_proxy_var_new(&self->super, "permit_unicode_url",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->permit_unicode_url);

  z_proxy_var_new(&self->super, "permit_invalid_hex_escape",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->permit_invalid_hex_escape);

  z_proxy_var_new(&self->super, "permit_http09_responses",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->permit_http09_responses);

  z_proxy_var_new(&self->super, "permit_ftp_over_http",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->permit_ftp_over_http);

  /* close or keep-alive */
  z_proxy_var_new(&self->super, "connection_mode",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET,
                  &self->connection_mode);

  z_proxy_var_new(&self->super, "keep_persistent",
                  Z_VAR_TYPE_INT | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG | Z_VAR_GET,
                  &self->keep_persistent);

  /* string containing parent proxy */
  z_proxy_var_new(&self->super, "parent_proxy",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  self->parent_proxy);

  /* parent proxy port */
  z_proxy_var_new(&self->super, "parent_proxy_port",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->parent_proxy_port);

  /* default port if portnumber is not specified in urls */
  z_proxy_var_new(&self->super, "default_port",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  "default_http_port");

  z_proxy_var_new(&self->super, "use_default_port_in_transparent_mode",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->use_default_port_in_transparent_mode);

  z_proxy_var_new(&self->super, "use_canonicalized_urls",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->use_canonicalized_urls);

  z_proxy_var_new(&self->super, "default_http_port",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->default_http_port);

  z_proxy_var_new(&self->super, "default_https_port",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->default_https_port);

  z_proxy_var_new(&self->super, "default_ftp_port",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->default_ftp_port);

  /* rewrite host header when redirecting */
  z_proxy_var_new(&self->super, "rewrite_host_header",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->rewrite_host_header);

  z_proxy_var_new(&self->super, "reset_on_close",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->reset_on_close);

  /* require host header */
  z_proxy_var_new(&self->super, "require_host_header",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->require_host_header);

  /* enable strict header checking */
  z_proxy_var_new(&self->super, "strict_header_checking",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->strict_header_checking);

  /* enable strict header checking */
  z_proxy_var_new(&self->super, "strict_header_checking_action",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->strict_header_checking_action);

  /* integer */
  z_proxy_var_new(&self->super, "max_line_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->max_line_length);

  /* integer */
  z_proxy_var_new(&self->super, "max_url_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->max_url_length);

  /* integer */
  z_proxy_var_new(&self->super, "max_hostname_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->max_hostname_length);

  /* integer */
  z_proxy_var_new(&self->super, "max_header_lines",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->max_header_lines);

  /* integer */
  z_proxy_var_new(&self->super, "max_keepalive_requests",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->max_keepalive_requests);

  /* integer */
  z_proxy_var_new(&self->super, "max_body_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->max_body_length);

  /* integer */
  z_proxy_var_new(&self->super, "max_chunk_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->max_chunk_length);

  /* integer */
  z_proxy_var_new(&self->super, "request_count",
                  Z_VAR_TYPE_INT | Z_VAR_GET,
                  &self->request_count);

  /* timeout value in milliseconds */
  z_proxy_var_new(&self->super, "timeout",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->timeout);

  /* timeout value in milliseconds */
  z_proxy_var_new(&self->super, "buffer_size",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->buffer_size);

  /* request timeout value in milliseconds */
  z_proxy_var_new(&self->super, "timeout_request",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG,
                  &self->timeout_request);

  /* response timeout value in milliseconds */
  z_proxy_var_new(&self->super, "timeout_response",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG,
                  &self->timeout_response);

  /* number of rerequest attempts */
  z_proxy_var_new(&self->super, "rerequest_attempts",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG,
                  &self->rerequest_attempts);

  /* hash indexed by request method */
  z_proxy_var_new(&self->super, "request",
                  Z_VAR_TYPE_HASH | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  self->request_method_policy);

  /* hash indexed by header name */
  z_proxy_var_new(&self->super, "request_header",
                  Z_VAR_TYPE_HASH | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  self->request_header_policy);

  /* string containing current request headers as a raw string */
  z_proxy_var_new(&self->super, "request_headers_flat",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_headers_flat, NULL, NULL);

  /* hash indexed by response code */
  z_proxy_var_new(&self->super, "response",
                  Z_VAR_TYPE_DIMHASH | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  self->response_policy);

  /* hash indexed by header name */
  z_proxy_var_new(&self->super, "response_header",
                  Z_VAR_TYPE_HASH | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  self->response_header_policy);

  /* string containing current response headers as a raw string */
  z_proxy_var_new(&self->super, "response_headers_flat",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_response_headers_flat, NULL, NULL);

  /* header manipulation */
  z_proxy_var_new(&self->super, "_AbstractHttpProxy__headerManip",
                  Z_VAR_TYPE_METHOD | Z_VAR_GET,
                  self, http_policy_header_manip);

  /* string containing current url proto */
  z_proxy_var_new(&self->super, "request_method",
                  Z_VAR_TYPE_STRING | Z_VAR_GET,
                  self->request_method);

  /* string containing current url version */
  z_proxy_var_new(&self->super, "request_version",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_version, NULL, NULL);

  /* string containing current url */
  z_proxy_var_new(&self->super, "request_url",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET | Z_VAR_SET,
                  NULL, http_query_request_url, http_set_request_url, NULL);

  /* string containing current url proto */
  z_proxy_var_new(&self->super, "request_url_proto",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing current url proto */
  z_proxy_var_new(&self->super, "request_url_scheme",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing current url username */
  z_proxy_var_new(&self->super, "request_url_username",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing current url passwd */
  z_proxy_var_new(&self->super, "request_url_passwd",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing current url hostname */
  z_proxy_var_new(&self->super, "request_url_host",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing current url port */
  z_proxy_var_new(&self->super, "request_url_port",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing current url file */
  z_proxy_var_new(&self->super, "request_url_file",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing current url query */
  z_proxy_var_new(&self->super, "request_url_query",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing current url fragment */
  z_proxy_var_new(&self->super, "request_url_fragment",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing request mime type */
  z_proxy_var_new(&self->super, "request_mime_type",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_mime_type, NULL, NULL);

  /* string containing response mime type */
  z_proxy_var_new(&self->super, "response_mime_type",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_mime_type, NULL, NULL);

  /* string containing current header name */
  z_proxy_var_new(&self->super, "current_header_name",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->current_header_name);

  /* string containing current header value */
  z_proxy_var_new(&self->super, "current_header_value",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->current_header_value);

  /* error response */
  z_proxy_var_new(&self->super, "error_status",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->error_status);

  /* error silence */
  z_proxy_var_new(&self->super, "error_silent",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->error_silent);

  /* string inserted into error messages */
  z_proxy_var_new(&self->super, "error_info",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->error_info);

  z_proxy_var_new(&self->super, "error_msg",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->error_msg);

  z_proxy_var_new(&self->super, "error_headers",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->error_headers);

  z_proxy_var_new(&self->super, "custom_response_body",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->custom_response_body);

  z_proxy_var_new(&self->super, "auth_forward",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG,
                  &self->auth_forward);

  z_proxy_var_new(&self->super, "auth",
                  Z_VAR_TYPE_OBJECT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->auth);

  z_proxy_var_new(&self->super, "auth_realm",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  self->auth_realm);

  z_proxy_var_new(&self->super, "max_auth_time",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->max_auth_time);

  z_proxy_var_new(&self->super, "target_port_range",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG,
                  self->target_port_range);

  z_proxy_var_new(&self->super, "error_files_directory",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG,
                  self->error_files_directory);

  /* compatibility with Zorp 0.8.x */
  z_proxy_var_new(&self->super, "transparent_server_requests",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  "permit_server_requests");

  z_proxy_var_new(&self->super, "transparent_proxy_requests",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  "permit_proxy_requests");

  z_proxy_var_new(&self->super, "request_timeout",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG,
                  "timeout_request");

  z_proxy_var_new(&self->super, "request_headers",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  "request_header");

  z_proxy_var_new(&self->super, "response_headers",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  "response_header");

  z_proxy_var_new(&self->super, "url_proto",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET,
                  "request_url_proto");

  z_proxy_var_new(&self->super, "url_username",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET,
                  "request_url_username");

  z_proxy_var_new(&self->super, "url_passwd",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET,
                  "request_url_passwd");

  z_proxy_var_new(&self->super, "url_host",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET,
                  "request_url_host");

  z_proxy_var_new(&self->super, "url_port",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET,
                  "request_url_port");

  z_proxy_var_new(&self->super, "url_file",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET,
                  "request_url_file");

  z_proxy_var_new(&self->super, "error_response",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET | Z_VAR_SET,
                  "error_status");

  z_proxy_var_new(&self->super, "request_host",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET,
                  "request_url_host");

  z_proxy_var_new(&self->super, "auth_by_cookie",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->auth_by_cookie);

  z_proxy_var_new(&self->super, "auth_by_form",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->auth_by_form);

  z_proxy_var_new(&self->super, "login_page_path",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  self->login_page_path);

  z_proxy_var_new(&self->super, "auth_cache_time",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->auth_cache_time);

  z_proxy_var_new(&self->super, "auth_cache_update",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->auth_cache_update);

  z_proxy_var_new(&self->super, "enable_url_filter",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->enable_url_filter);

  z_proxy_var_new(&self->super, "enable_url_filter_dns",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->enable_url_filter_dns);

  z_proxy_var_new(&self->super, "url_filter_uncategorized_action",
                  Z_VAR_TYPE_OBJECT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->url_filter_uncategorized_action);

  /* hash indexed by url category */
  z_proxy_var_new(&self->super, "url_category",
                  Z_VAR_TYPE_HASH | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  self->url_category);

  z_proxy_var_new(&self->super, "request_categories",
                  Z_VAR_TYPE_OBJECT | Z_VAR_GET,
                  &self->request_categories);

  z_proxy_return(self);
}

static std::string
http_error_file_path(HttpProxy *self, const std::string &filename)
{
  std::string file_path;
  if (self->error_files_directory->len)
    file_path = std::string(self->error_files_directory->str) + "/" + filename;
  else
    file_path = ZORP_DATADIR "/http/" + std::string(self->super.language->str) + "/" + filename;

  return file_path;
}

/**
 * http_error_message:
 * @self: HttpProxy instance
 * @response_code: HTTP status code to return
 * @message_code: HTTP message code (one of HTTP_MSG_*)
 * @infomsg: additional information added into error messages
 *
 * This function formats and returns an error page to the client when its
 * request cannot be fulfilled. It switches to non-persistent mode and
 * prepares the proxy for shutdown.
 **/
static gboolean
http_error_message(HttpProxy *self, gint response_code, guint message_code, GString *infomsg)
{
  const gchar *messages[] =
    {
      NULL,
      "clientsyntax.html",
      "serversyntax.html",
      "policysyntax.html",
      "policyviolation.html",
      "invalidurl.html",
      "connecterror.html",
      "ioerror.html",
      "auth.html",
      "clienttimeout.html",
      "servertimeout.html",
      "badcontent.html",
      "ftperror.html",
      "redirect.html",
      "internal.html"
    };
  gchar response[256];
  gchar *error_msg;

  z_proxy_enter(self);

  if (message_code != HTTP_MSG_CONNECT_ERROR)
    {
      z_policy_lock(self->super.thread);
      z_proxy_report_policy_abort(&(self->super));
      z_policy_unlock(self->super.thread);
    }

  if (message_code >= (sizeof(messages) / sizeof(char *)))
    {
      /*LOG
        This message indicates that Zorp caught an invalid error code
        internally. Please report this event to the BalaSys Development Team
	(at devel@balasys.hu).
      */
      z_proxy_log(self, HTTP_ERROR, 2, "Internal error, error code out of range; error_code='%d'", message_code);
      z_proxy_return(self, FALSE);
    }

  if (message_code == 0)
    z_proxy_return(self, TRUE);

  if (self->proto_version[EP_CLIENT] >= 0x0100)
    {
      g_snprintf(response, sizeof(response), "HTTP/1.0 %d %s\r\n", response_code, self->error_msg->len > 0 ? self->error_msg->str : "Error encountered");

      if (http_write(self, EP_CLIENT, response, strlen(response)) != G_IO_STATUS_NORMAL)
        z_proxy_return(self, FALSE); /* error writing error message is already sent by http_write */

      /* FIXME: we should not use self->headers[EP_SERVER] for this purpose */
      g_string_truncate(self->headers[EP_SERVER].flat, 0);

      if (!self->transparent_mode)
        g_string_append(self->headers[EP_SERVER].flat, "Proxy-Connection: close\r\n");
      else
        g_string_append(self->headers[EP_SERVER].flat, "Connection: close\r\n");

      g_string_append(self->headers[EP_SERVER].flat, self->error_headers->str);
      g_string_append(self->headers[EP_SERVER].flat, "Content-Type: text/html\r\n\r\n");

      if (http_write(self, EP_CLIENT, self->headers[EP_SERVER].flat->str, self->headers[EP_SERVER].flat->len) != G_IO_STATUS_NORMAL)
        z_proxy_return(self, FALSE);
    }
  else if (message_code == HTTP_MSG_CLIENT_TIMEOUT)
    {
      z_proxy_log(self, HTTP_DEBUG, 6, "Client has timed out, would serve error file, but silent mode is always enabled for this case;");
      return false;
    }

  if ((self->request_flags & HTTP_REQ_FLG_HEAD))
    z_proxy_return(self, TRUE); /* we are responding to a HEAD request, do not return a body */

  const std::string filename = http_error_file_path(self, messages[message_code]);

  if (self->error_silent)
    {
      /*LOG
        This message reports that Zorp would send the given error page to
        the browser, if silent mode would not be enabled. It is likely that
        some protocol/configuration/proxy error occurred.
      */
      z_proxy_log(self, HTTP_DEBUG, 6, "An error occurred, would serve error file, but silent mode is enabled; filename='%s'", filename.c_str());
      z_proxy_return(self, FALSE);
    }

  /*LOG
    This message reports that Zorp is sending the given error page to the
    clients browser. It is likely that some protocol/configuration/proxy
    error occurred.
  */
  z_proxy_log(self, HTTP_DEBUG, 6, "An error occurred, serving error file; filename='%s'", filename.c_str());
  error_msg = z_error_loader_format_file(filename.c_str(), infomsg->str, Z_EF_ESCAPE_HTML, NULL, NULL);

  if (error_msg)
    {
      http_write(self, EP_CLIENT, error_msg, strlen(error_msg));
      g_free(error_msg);
    }

  z_proxy_return(self, TRUE);
}

/**
 * Send a locally generated response back to the client
 *
 * The response will be sent back as is, with the supplied status info and headers.
 * The empty line between the headers and response body will be added automatically.
 * Note that a Content-Length header should be included in the headers, depending on the
 * request method and the status code, as described in rfc2616.
 * A Connection: close header will be added automatically.
 *
 * @param self The proxy.
 * @param status_code Status code to use in the status line.
 * @param status_msg Status message to use in the status line.
 * @param headers Flat string containing all the headers to send to the client.
 * @param response_body Response body to send to the client. May be empty.
 */
static void
http_send_custom_response(HttpProxy *self, guint status_code, GString *status_msg, GString *headers, GString *response_body)
{
  gchar status_line[256];
  gsize response_body_length = response_body ? response_body->len : 0;
  /* Preallocate some space for the response:
   * status line + error headers + appended headers + empty line + response body
   */
  GString *http_response = g_string_sized_new(sizeof(status_line)
                                              + headers->len +
                                              + 32 + 2
                                              + response_body_length);


  g_snprintf(status_line, sizeof(status_line), "HTTP/1.0 %d %s\r\n",
             status_code, status_msg->len > 0 ? status_msg->str : "Error encountered");

  g_string_append(http_response, status_line);
  g_string_append(http_response, headers->str);

  g_string_append(http_response, "Connection: close\r\n");
  g_string_append(http_response, "\r\n");

  if (response_body_length > 0)
    g_string_append(http_response, response_body->str);

  z_log(NULL, HTTP_DEBUG, 6, "Sending custom response back to the client; length='%" G_GSIZE_FORMAT "'", http_response->len);

  if (http_write(self, EP_CLIENT, http_response->str, http_response->len) != G_IO_STATUS_NORMAL)
    z_log(NULL, HTTP_ERROR, 4, "Error sending custom response back to the client;");

  g_string_free(http_response, TRUE);
}

/**
 * http_client_stream_init:
 * @self: HttpProxy instance
 *
 * This function is called upon startup to initialize our client stream.
 **/
static gboolean
http_client_stream_init(HttpProxy *self)
{
  ZStream *tmpstream;
  z_proxy_enter(self);

  z_proxy_enter(self);
  tmpstream = self->super.endpoints[EP_CLIENT];
  self->super.endpoints[EP_CLIENT] = z_stream_line_new(tmpstream, self->max_line_length, ZRL_EOL_CRLF | ZRL_PARTIAL_READ);
  z_stream_unref(tmpstream);
  /* timeout is initialized after the config event */
  z_proxy_return(self, TRUE);
}

/**
 * http_server_stream_init:
 * @self: HttpProxy instance
 *
 * This function is called upon startup to initialize our server stream.
 **/
static gboolean
http_server_stream_init(HttpProxy *self)
{
  ZStream *tmpstream;
  z_proxy_enter(self);

  z_proxy_enter(self);
  tmpstream = self->super.endpoints[EP_SERVER];
  self->super.endpoints[EP_SERVER] = z_stream_line_new(tmpstream, self->max_line_length, ZRL_EOL_CRLF | ZRL_PARTIAL_READ);
  z_stream_unref(tmpstream);
  self->super.endpoints[EP_SERVER]->timeout = self->timeout;
  z_proxy_return(self, TRUE);
}

/**
 * http_server_stream_is_initialized:
 * @self: HttpProxy instance
 *
 * This function returns whether or not the server stream has already
 * been initialized. Currently, it just checks if a StreamLine has been
 * pushed onto the stack.
 */
static gboolean
http_server_stream_is_initialized(HttpProxy *self)
{
  gboolean res;

  z_proxy_enter(self);

  res = (z_stream_search_stack(self->super.endpoints[EP_SERVER], G_IO_IN, Z_CLASS(ZStreamLine)) != NULL);

  z_proxy_return(self, res);
}

GIOStatus
http_write(HttpProxy *self, guint side, gchar *buf, size_t buflen)
{
  GIOStatus res;
  gsize bytes_written;

  z_proxy_enter(self);

  if (!self->super.endpoints[side])
    {
      /*LOG
        This message reports that Zorp was about to write to an invalid
        stream. Please report this event to the BalaSys Development Team (at
        devel@balasys.hu).
      */
      z_proxy_log(self, HTTP_ERROR, 1, "Error writing stream, stream is NULL; side='%s'", side == EP_CLIENT ? "client" : "server");
      z_proxy_return(self, G_IO_STATUS_ERROR);
    }

  res = z_stream_write(self->super.endpoints[side], buf, buflen, &bytes_written, NULL);

  if (res != G_IO_STATUS_NORMAL || buflen != bytes_written)
    {
      /* FIXME: move this to a separate function */
      /*LOG
        This message reports that Zorp was unable to write to the given
        stream. It is likely that the peer closed the connection
        unexpectedly.
      */
      z_proxy_log(self, HTTP_ERROR, 1, "Error writing stream; side='%s', res='%x', error='%s'", side == EP_CLIENT ? "client" : "server", res, g_strerror(errno));

      self->error_code = HTTP_MSG_IO_ERROR;
      self->error_status = 502;
      g_string_sprintf(self->error_info, "Error writing to %s (%s)", side == EP_CLIENT ? "client" : "server", g_strerror(errno));
      z_proxy_return(self, G_IO_STATUS_ERROR);
    }

  z_proxy_return(self, res);
}

static int
http_parse_connection_hdr_value(HttpProxy *self, HttpHeader *hdr)
{
  z_proxy_enter(self);

  if (strcasecmp(hdr->value->str, "keep-alive") == 0)
    z_proxy_return(self, HTTP_CONNECTION_KEEPALIVE);
  else if (strcasecmp(hdr->value->str, "close") == 0)
    z_proxy_return(self, HTTP_CONNECTION_CLOSE);

  z_proxy_log(self, HTTP_ERROR, 4, "Unknown connection header value; value='%s'", hdr->value->str);
  z_proxy_return(self, HTTP_CONNECTION_UNKNOWN);
}

static void
http_assign_connection_hdr_value(HttpProxy *self, GString *value)
{
  z_proxy_enter(self);

  if (self->connection_mode == HTTP_CONNECTION_KEEPALIVE)
    g_string_assign(value, "keep-alive");
  else if (self->connection_mode == HTTP_CONNECTION_CLOSE)
    g_string_assign(value, "close");

  z_proxy_return(self);
}

static inline gboolean
http_parent_proxy_enabled(HttpProxy *self)
{
  return !!self->parent_proxy->len;
}

static gboolean
http_decode_base64(gchar *dst, guint dstlen, const gchar *src, guint srclen)
{
  z_enter();
  ZCode * base64_decode = z_code_base64_decode_new(0, FALSE);

  if (!z_code_transform(base64_decode, src, srclen) ||
      !z_code_finish(base64_decode))
    {
      z_code_free(base64_decode);
      z_return(FALSE);
    }

  dstlen = z_code_get_result(base64_decode, dst, dstlen - 1);
  dst[dstlen] = 0;
  z_code_free(base64_decode);
  z_return(TRUE);
}

static std::string
http_encode_base64(const std::string &src)
{
  z_enter();
  ZCode *base64_encode = z_code_base64_encode_new(0, 0);

  if (!z_code_transform(base64_encode, src.c_str(), src.length()) ||
      !z_code_finish(base64_encode))
    {
      z_code_free(base64_encode);
      z_return("");
    }

  gsize retlen = z_code_get_result_length(base64_encode);
  char *dst = g_new(gchar, retlen + 1);
  gsize dstlen = z_code_get_result(base64_encode, dst, retlen);
  std::string result(dst, dstlen);
  g_free(dst);
  z_code_free(base64_encode);
  z_return(result);
}

static bool
http_do_authenticate(HttpProxy *self, ZorpAuthInfo *auth_info, const std::string &username, const std::string &password)
{
  z_policy_lock(self->super.thread);
  bool res = z_auth_provider_check_passwd(self->auth, self->super.session_id, const_cast<gchar*>(username.c_str()), const_cast<gchar *>(password.c_str()), &auth_info->groups, &self->super);
  z_policy_unlock(self->super.thread);

  if (res)
    {
      res = z_proxy_user_authenticated_default(&self->super, username.c_str(), (const gchar **)auth_info->groups);
      G_LOCK(auth_mutex);

      if (self->auth_cache_time > 0)
        {
          auth_info->last_auth_time = time(NULL);
        }

      g_free(auth_info->username);
      auth_info->username = g_strdup(username.c_str());

      if (self->auth_forward)
        {
          z_proxy_log(self, HTTP_DEBUG, 5, "Assembling synthetic Authorization header for auth_forward;");

          std::string encoded_creds = http_encode_base64(username + ':' + password);
          if (encoded_creds.empty())
            {
              z_proxy_log(self, HTTP_ERROR, 3,
                          "Error encoding synthetic Authorization header for auth_forward;");
              res = FALSE;
            }
          else
            {
              encoded_creds.insert(0, "Basic ");
              auth_info->basic_auth_creds = g_strdup(encoded_creds.c_str());
            }
        }

      G_UNLOCK(auth_mutex);
    }
  return res;
}

/* FIXME: optimize header processing a bit (no need to copy hdr into a
   buffer) */
static gboolean
http_process_auth_info(HttpProxy *self, HttpHeader *h, ZorpAuthInfo *auth_info)
{
  gchar userpass[128];
  gchar *p;
  gchar **up;

  z_proxy_enter(self);

  if (self->old_auth_header->len &&
      strcmp(h->value->str, self->old_auth_header->str) == 0)
    z_proxy_return(self, TRUE);

  if (strncmp(h->value->str, "Basic", 5) != 0)
    {
      /*LOG
        This message indicates that the client tried to use the given
        unsupported HTTP authentication. Currently only Basic HTTP
        authentication is supported by Zorp.
      */
      z_proxy_log(self, HTTP_ERROR, 3, "Only Basic authentication is supported; authentication='%s'", h->value->str);
      /* not basic auth */
      z_proxy_return(self, FALSE);
    }

  p = h->value->str + 5;

  while (*p == ' ')
    p++;

  if (!http_decode_base64(userpass, sizeof(userpass), p, strlen(p)))
    {
      /*LOG
        This message indicates that the client sent a malformed
        username:password field, during the authentication phase.
      */
      z_proxy_log(self, HTTP_VIOLATION, 1, "Invalid base64 encoded username:password pair;");
      z_proxy_return(self, FALSE);
    }

  up = g_strsplit(userpass, ":", 2);

  if (up)
    {
      bool res = http_do_authenticate(self, auth_info, up[0], up[1]);
      if (res)
        g_string_assign(self->old_auth_header, h->value->str);

      g_strfreev(up);
      z_proxy_return(self, res);
    }

  /*LOG
    This message indicates that the username:password field received
    during authentication was malformed.
  */
  z_proxy_log(self, HTTP_VIOLATION, 2, "No colon is found in the decoded username:password pair;");
  z_proxy_return(self, FALSE);
}

static gboolean
http_rewrite_host_header(HttpProxy *self, gchar *host, gint host_len, guint port, guint server_protocol)
{
  HttpHeader *h;
  guint rfc_port = 80;

  z_proxy_enter(self);

  if (server_protocol == HTTP_PROTO_HTTPS)
    rfc_port = 443;

  if (self->rewrite_host_header && http_lookup_header(&self->headers[EP_CLIENT], "Host", &h))
    {
      /* NOTE: the constant rfc_port below is intentional, if
       * default_port is changed we still have to send
       * correct host header (containing port number)
       */
      if (port != rfc_port && port != 0)
        g_string_sprintf(h->value, "%.*s:%d", host_len, host, port);
      else
        g_string_sprintf(h->value, "%.*s", host_len, host);
    }

  z_proxy_return(self, TRUE);
}

static gboolean
http_format_request(HttpProxy *self, gboolean stacked, GString *request)
{
  gboolean res = TRUE;
  const gchar *reason;
  GString *url = g_string_sized_new(self->request_url->len);

  z_proxy_enter(self);

  if (self->proto_version[EP_CLIENT] >= 0x0100)
    {
      if (self->request_flags & HTTP_REQ_FLG_CONNECT)
        {
          g_assert(http_parent_proxy_enabled(self));

          http_flat_headers(&self->headers[EP_CLIENT]);
          g_string_sprintf(request, "%s %s %s\r\n%s\r\n",
                           self->request_method->str, self->request_url->str, self->request_version,
                           self->headers[EP_CLIENT].flat->str);
        }
      else
        {
          if (!stacked)
            {
              http_flat_headers(&self->headers[EP_CLIENT]);

              if (!http_format_url(&self->request_url_parts, url, http_parent_proxy_enabled(self), self->permit_unicode_url, self->use_canonicalized_urls, &reason))
                res = FALSE;

#define g_string_append_gstring(r, s) g_string_append_len(r, s->str, s->len)
#define g_string_append_const(r, s) g_string_append_len(r, s, __builtin_strlen(s))

              /* slightly less than a page to make sure it fits on a page even with the malloc overhead */
              g_string_set_size(request, 4000);
              g_string_truncate(request, 0);
              g_string_append_gstring(request, self->request_method);
              g_string_append_c(request, ' ');
              g_string_append_gstring(request, url);
              g_string_append_c(request, ' ');
              g_string_append(request, self->request_version);
              g_string_append_const(request, "\r\n");
              g_string_append_gstring(request, self->headers[EP_CLIENT].flat);
              g_string_append_const(request, "\r\n");
            }
          else
            {
              http_flat_headers_into(&self->headers[EP_CLIENT], request);
            }
        }
    }
  else
    {
      if (!http_format_url(&self->request_url_parts, url, FALSE, self->permit_unicode_url, self->use_canonicalized_urls, &reason))
        res = FALSE;
      else
        g_string_sprintf(request, "%s %s\r\n", self->request_method->str, url->str);
    }

  if (!res)
    z_proxy_log(self, HTTP_ERROR, 3, "Error reformatting requested URL; url='%s', reason='%s'", self->request_url->str, reason);

  g_string_free(url, TRUE);
  z_proxy_return(self, res);
}

static gboolean
http_format_early_request(HttpProxy *self, gboolean stacked, GString *preamble)
{
  if (stacked)
    return http_format_request(self, stacked, preamble);
  else
    g_string_assign(preamble, "");

  return TRUE;
}

bool
http_query_string_get_value(const std::string &stream_line, const std::string &key, std::string &value)
{
  std::string::size_type start_from = 0;

  while (start_from != std::string::npos)
    {
      const std::string::size_type equal_pos = stream_line.find("=", start_from);
      const std::string::size_type and_pos = stream_line.find('&', equal_pos + 1);

      if (equal_pos == std::string::npos)
        {
          return false;
        }

      if (!stream_line.compare(start_from, equal_pos - start_from, key))
        {
          std::string::size_type value_len = and_pos;

          if (and_pos != std::string::npos)
            {
              value_len = and_pos - equal_pos - 1;
            }

          value = stream_line.substr(equal_pos + 1, value_len);
          return true;
        }

      start_from = and_pos;
      if (and_pos != std::string::npos)
        start_from++;
    }

  return false;
}

static bool
http_form_auth_get_item(HttpProxy *self, const std::string &stream_line, const std::string &key, std::string &value,
                        const bool mandatory = false)
{
  if (!http_query_string_get_value(stream_line, key, value))
    {
      if (mandatory)
        z_proxy_log(self, HTTP_ERROR, 3, "HTTP auth form's reply does not contain a mandatory input item; inputname='%s'", key.c_str());
      else
        z_proxy_log(self, HTTP_INFO, 3, "HTTP auth form's reply does not contain an optional input item, "
                                        "but the request processing can continue; inputname='%s'", key.c_str());

      return false;
    }

  const gchar *reason;
  GString *decoded = g_string_new("");
  if (http_string_assign_form_url_decode(decoded, TRUE, value.c_str(), value.length(), &reason))
    {
      value = decoded->str;
    }
  g_string_free(decoded, TRUE);

  return true;
}

static bool
http_form_auth_get_username_password_redirect(HttpProxy *self, const std::string &stream_line, std::string &username,
                                              std::string &password, std::string &redirect_location)
{
  if (!http_form_auth_get_item(self, stream_line, "username", username, true) ||
      !http_form_auth_get_item(self, stream_line, "password", password, true))
    return false;

  http_form_auth_get_item(self, stream_line, "redirect_location", redirect_location, false);
  return true;
}

static std::string
http_form_auth_get_first_post_line(HttpProxy *self)
{
  std::string post_line;

  std::unique_ptr<ZBlob, std::function<void(ZBlob*)>> blob(
    z_blob_new(nullptr, 0),
    std::bind(&z_blob_unref, std::placeholders::_1)
  );
  if (!blob)
    return post_line;

  std::string session_id = std::string(self->super.session_id) + "/post";
  std::unique_ptr<ZStream, std::function<void(ZStream*)>> blob_stream(
    z_stream_blob_new(blob.get(), session_id.c_str()),
    std::bind(&z_stream_unref, std::placeholders::_1)
  );
  blob_stream->timeout = -1;
  if (!http_data_transfer(self, HTTP_TRANSFER_TO_BLOB, EP_CLIENT, self->super.endpoints[EP_CLIENT], EP_SERVER, blob_stream.get(), false, false, http_format_early_request))
    {
      return post_line;
    }

  std::unique_ptr<ZStream, std::function<void(ZStream*)>> stream_line(
    z_stream_push(z_stream_blob_new(blob.get(), session_id.c_str()), z_stream_line_new(nullptr, self->max_line_length, ZRL_EOL_CRLF | ZRL_PARTIAL_READ)),
    [] (ZStream *stream) {
      ZStream *tmpstream = z_stream_pop(stream);
      z_stream_unref(tmpstream);
    }
  );

  gchar *line;
  gsize line_length;
  bool res = z_stream_line_get(stream_line.get(), &line, &line_length, nullptr);
  if (line_length == 0)
    return post_line;

  post_line = std::string(line).substr(0, line_length);

  return post_line;
}

static void
http_form_auth_set_answer(HttpProxy *self, const std::string &redirect_location)
{
  if (redirect_location.empty())
    {
      self->error_code = HTTP_MSG_OK;
      self->error_status = 200;
      g_string_assign(self->custom_response_body, "You are now authorized.");
    }
  else
    {
      self->error_code = HTTP_MSG_REDIRECT;
      self->error_status = 301;
      g_string_assign(self->error_info, redirect_location.c_str());
      g_string_sprintfa(self->error_headers, "Location: %s\r\n", redirect_location.c_str());
    }
  self->send_custom_response = TRUE;
}

static bool
http_get_form_auth(HttpProxy *self, ZorpAuthInfo *auth_info, std::string &redirect_location)
{
  HttpHeader *header, *transfer_encoding_header;

  if (!(self->request_flags & HTTP_REQ_FLG_POST))
    {
      z_proxy_log(self, HTTP_ERROR, 3, "HTTP auth form reply's method is not POST;");
      return false;
    }

  if (!http_lookup_header(&self->headers[EP_CLIENT], "Transfer-Encoding", &transfer_encoding_header) &&
      !http_lookup_header(&self->headers[EP_CLIENT], "Content-Length", &header))
    {
      z_proxy_log(self, HTTP_ERROR, 3, "HTTP auth form reply's does not contain either "
                                       "Content-Length or Transfer-Encoding header;");
      return false;
    }

  if (transfer_encoding_header &&
      (strcasecmp(transfer_encoding_header->value->str, "chunked") &&
       strcasecmp(transfer_encoding_header->value->str, "identity")))
    {
      z_proxy_log(self, HTTP_ERROR, 3, "HTTP auth form reply's Transfer-Encoding is not supported, "
                                       "only chunked and identity are allowed; transfer_encoding='%s'",
                                       transfer_encoding_header->value->str);
      return false;
    }

  const char *content_type = "application/x-www-form-urlencoded";
  if (!http_lookup_header(&self->headers[EP_CLIENT], "Content-Type", &header) ||
      strncmp(header->value->str, content_type, sizeof(content_type)-1))
    {
      z_proxy_log(self, HTTP_ERROR, 3, "HTTP auth form reply's Content-Type is not %s;", content_type);
      return false;
    }

  const std::string charset_delimeter = "charset=";
  std::string content_type_value(header->value->str);
  std::string::size_type charset_pos = content_type_value.find(charset_delimeter);
  if (charset_pos != std::string::npos)
    {
      std::string charset = content_type_value.substr(charset_pos + charset_delimeter.length());
      std::transform(charset.begin(), charset.end(), charset.begin(),
                     [](unsigned char c){ return std::toupper(c); });

      if (charset.find("UTF-8") == std::string::npos &&
          charset.find("US-ASCII") == std::string::npos)
        {
          z_proxy_log(self, HTTP_ERROR, 3, "HTTP auth form reply's charset is not supported; charset='%s'", charset.c_str());
          return false;
        }
    }

  std::string post_line = http_form_auth_get_first_post_line(self);
  if (post_line.empty())
    return false;

  std::string username, password;
  if (!http_form_auth_get_username_password_redirect(self, post_line, username, password, redirect_location))
    return false;

  bool res = http_do_authenticate(self, auth_info, username, password);
  if (res)
    {
      http_form_auth_set_answer(self, redirect_location);
    }

  return res;
}

static gboolean
http_fetch_request(HttpProxy *self)
{
  gchar *line;
  gsize line_length;
  gint empty_lines = 0;
  guint res;

  z_proxy_enter(self);
  /* FIXME: this can probably be removed as http_fetch_header does this */
  http_clear_headers(&self->headers[EP_CLIENT]);

  while (empty_lines < HTTP_MAX_EMPTY_REQUESTS)
    {
      self->super.endpoints[EP_CLIENT]->timeout = self->timeout_request;
      res = z_stream_line_get(self->super.endpoints[EP_CLIENT], &line, &line_length, NULL);
      self->super.endpoints[EP_CLIENT]->timeout = self->timeout;

      if (res == G_IO_STATUS_EOF)
        {
          self->error_code = HTTP_MSG_OK;
          z_proxy_return(self, FALSE);
        }

      if (res != G_IO_STATUS_NORMAL)
        {
          self->error_code = HTTP_MSG_OK;

          if (errno == ETIMEDOUT)
            {
              if (self->request_count == 0)
                {
                  self->error_code = HTTP_MSG_CLIENT_TIMEOUT;
                  self->error_status = 408;
                }
            }

          z_proxy_return(self, FALSE);
        }

      if (line_length != 0)
        break;

      empty_lines++;
    }

  if (!http_split_request(self, line, line_length))
    {
      g_string_assign(self->error_info, "Invalid request line.");
      /*LOG
        This message indicates that the client sent an invalid HTTP request
        to the proxy.
      */
      z_proxy_log(self, HTTP_VIOLATION, 2, "Invalid HTTP request received; line='%.*s'", (gint)line_length, line);
      z_proxy_return(self, FALSE);
    }

  self->request_flags = http_proto_request_lookup(self->request_method->str);

  if (!http_parse_version(self, EP_CLIENT, self->request_version))
    z_proxy_return(self, FALSE); /* parse version already logged */

  if (!http_fetch_headers(self, EP_CLIENT))
    z_proxy_return(self, FALSE); /* fetch headers already logged */

  if (self->rerequest_attempts > 0)
    {
      HttpHeader *transfer_encoding_hdr, *content_length_hdr;
      gboolean has_data = FALSE;

      if (http_lookup_header(&self->headers[EP_CLIENT], "Transfer-Encoding", &transfer_encoding_hdr))
        has_data = TRUE;

      if (http_lookup_header(&self->headers[EP_CLIENT], "Content-Length", &content_length_hdr))
        has_data = TRUE;

      self->request_data_stored = TRUE;

      if (self->request_data)
        z_blob_truncate(self->request_data, 0, -1);

      if (has_data)
        {
          gchar session_id[MAX_SESSION_ID];
          ZStream *blob_stream;
          gboolean success;

          if (!self->request_data)
            self->request_data = z_blob_new(NULL, 0);

          if (!self->request_data)
            z_proxy_return(self, FALSE);

          g_snprintf(session_id, sizeof(session_id), "%s/post", self->super.session_id);
          blob_stream = z_stream_blob_new(self->request_data, session_id);
          blob_stream->timeout = -1;
          /* fetch data associated with request */
          success = http_data_transfer(self, HTTP_TRANSFER_TO_BLOB, EP_CLIENT, self->super.endpoints[EP_CLIENT], EP_SERVER, blob_stream, FALSE, FALSE, http_format_early_request);
          z_stream_unref(blob_stream);

          if (!success)
            z_proxy_return(self, FALSE);
        }
    }

  z_proxy_return(self, TRUE);
}

static gboolean
http_auth_is_expired(gpointer  /* key */, gpointer value, gpointer user_data)
{
  ZorpAuthInfo *real_value = static_cast<ZorpAuthInfo *>(value);
  time_t max_time = MAX(MAX(real_value->last_auth_time, real_value->accept_credit_until), real_value->created_at);
  time_t cut_time = GPOINTER_TO_UINT(user_data);

  return (max_time < cut_time);
}

static void
http_auth_destroy(gpointer value)
{
  ZorpAuthInfo *real_value = static_cast<ZorpAuthInfo *>(value);

  g_free(real_value->username);
  g_strfreev(real_value->groups);
  g_free(real_value->basic_auth_creds);
  g_free(real_value);
}

static inline gchar *
http_process_create_realm(HttpProxy *self, time_t now, gchar *buf, guint buflen)
{
  if (self->max_auth_time > 0)
    g_snprintf(buf, buflen, "Basic realm=\"%s (id:%x)\"", self->auth_realm->str, (int)now);
  else
    g_snprintf(buf, buflen, "Basic realm=\"%s\"", self->auth_realm->str);

  return buf;
}


static gboolean
http_extract_client_info_from_cookies(HttpProxy *self, gchar *key, const guint key_length)
{
  CookiePairVector cookie_vector = http_parse_header_cookie(&self->headers[EP_CLIENT]);
  if (! cookie_vector.empty())
    {
      // FIXME: for now only the first matching cookie will be used
      CookiePairVector::iterator cookie_pair = http_find_cookie_by_name(cookie_vector, HttpProxy::zorp_realm_cookie_name);
      if (cookie_pair != cookie_vector.end())
        {
          g_strlcpy(key, cookie_pair->second.c_str(), key_length);

          // removing the Zorp auth cookie, because of security reasons (information leaking)
          cookie_vector.erase(cookie_pair);

          http_write_header_cookie(&self->headers[EP_CLIENT], cookie_vector);

          return TRUE;
        }
    }

  return FALSE;
}

static gboolean
http_generate_client_info(gchar *key, const guint key_length)
{
  guchar raw_key[32];

  if (!z_random_sequence_get(Z_RANDOM_STRONG, raw_key, sizeof(raw_key)))
    return FALSE;

  ZCode * coder = z_code_base64_encode_new(256, 255);
  if (coder == NULL)
    return FALSE;

  if (!z_code_transform(coder, raw_key, sizeof(raw_key)) ||
      !z_code_finish(coder))
    return FALSE;

  gsize pos = z_code_get_result(coder, key, key_length - 1);
  key[pos-2] = 0;

  return TRUE;
}

static gboolean
http_get_client_info(HttpProxy *self, gchar *key, const guint key_length)
{
  if (http_extract_client_info_from_cookies(self, key, key_length) ||
      http_generate_client_info(key, key_length))
    return TRUE;

  return FALSE;
}

static gboolean
http_check_name(HttpProxy *self)
{
  z_proxy_enter(self);
  ZProxyHostIface *host_iface = Z_CAST(z_proxy_find_iface(&self->super, Z_CLASS(ZProxyHostIface)), ZProxyHostIface);

  if (host_iface == NULL)
    host_iface = Z_CAST(z_proxy_find_iface(self->super.parent_proxy, Z_CLASS(ZProxyHostIface)), ZProxyHostIface);

  if (host_iface)
    {
      gchar error_reason[256];

      if (!z_proxy_host_iface_check_name(host_iface, self->remote_server->str, error_reason, sizeof(error_reason)))
        {
          z_proxy_log(self, HTTP_ERROR, 3, "Error checking hostname; error='%s'", error_reason);
          g_string_assign(self->error_info, error_reason);
          z_proxy_return(self, FALSE);
        }

      z_object_unref(&host_iface->super);
    }

  z_proxy_return(self, TRUE);
}

static gint
http_get_default_port_for_protocol(HttpProxy *self)
{
  if (self->server_protocol == HTTP_PROTO_HTTP)
    return self->default_http_port;
  else if (self->server_protocol == HTTP_PROTO_HTTPS)
    return self->default_https_port;
  else
    return self->default_ftp_port;
}

static guint
http_get_request_type(HttpProxy *self)
{
  guint request_type;

  if (self->proto_version[EP_CLIENT] < 0x0100)
    {
      /* no proxy protocol for version 0.9 */
      request_type = HTTP_REQTYPE_SERVER;
    }
  else
    {
      if (self->request_url->str[0] == '/')
        request_type = HTTP_REQTYPE_SERVER;
      else
        request_type = HTTP_REQTYPE_PROXY;
    }

  return request_type;
}

static HttpHeader *
http_add_proxy_connection_header_as_connection_header(HttpProxy *self, HttpHeader *pconn_hdr)
{
  gchar header_name[] = "Connection";
  guint header_name_size = strlen(header_name);
  HttpHeader *conn_hdr = http_add_header(&self->headers[EP_CLIENT],
                                         header_name, header_name_size,
                                         pconn_hdr->value->str, pconn_hdr->value->len);
  return conn_hdr;
}

static gboolean
http_process_proxy_connection_header(HttpProxy *self)
{
  HttpHeader *pconn_hdr;
  HttpHeader *conn_hdr;

  gboolean has_proxy_conn_hdr = http_lookup_header(&self->headers[EP_CLIENT], "Proxy-Connection", &pconn_hdr);
  if (has_proxy_conn_hdr)
    {
      gboolean is_proxy_connection_header_possible = (self->proto_version[EP_CLIENT] >= 0x0100);
      if (!is_proxy_connection_header_possible)
        has_proxy_conn_hdr = FALSE;

      pconn_hdr->present = FALSE;
    }

  gboolean has_conn_hdr = http_lookup_header(&self->headers[EP_CLIENT], "Connection", &conn_hdr) &&
                          conn_hdr->present;
  gboolean has_proxy_connection_header_only = has_proxy_conn_hdr && !has_conn_hdr;
  if (has_proxy_connection_header_only)
    self->connection_hdr = http_add_proxy_connection_header_as_connection_header(self, pconn_hdr);
  else if (has_conn_hdr)
    self->connection_hdr = conn_hdr;

  return (self->connection_hdr != NULL);
}

static void
http_process_connection_headers(HttpProxy *self)
{
  self->connection_hdr = NULL;
  http_process_proxy_connection_header(self);
}

static void
http_iterate_connection_header_tokens(HttpHeaders *headers, HttpHeader *conn_hdr)
{
  const gchar *linear_white_spaces = " \t,";
  gchar **conn_hdr_tokens = g_strsplit_set(conn_hdr->value->str, linear_white_spaces, -1);
  GString *conn_hdr_new_value = g_string_sized_new(conn_hdr->value->len);
  for (gchar **conn_hdr_token = conn_hdr_tokens;
       *conn_hdr_token != NULL;
       conn_hdr_token++)
    {
      if (**conn_hdr_token == '\0')
        continue;

      HttpHeader *token_hdr;
      if (http_lookup_header(headers, *conn_hdr_token, &token_hdr))
        {
          token_hdr->present = FALSE;
        }
      else
        {
          if (conn_hdr_new_value->len)
            g_string_append_c(conn_hdr_new_value, ' ');
          g_string_append(conn_hdr_new_value, *conn_hdr_token);
        }
    }
  g_strfreev(conn_hdr_tokens);

  gboolean is_new_connection_hdr_empty = (conn_hdr_new_value->len == 0);
  if (is_new_connection_hdr_empty)
    conn_hdr->present = FALSE;
  else
    g_string_assign(conn_hdr->value, conn_hdr_new_value->str);

  g_string_free(conn_hdr_new_value, TRUE);
}

static void
http_process_connection_header_tokens(HttpHeaders *headers, HttpHeader *conn_hdr)
{
  http_iterate_connection_header_tokens(headers, conn_hdr);
}

static void
http_form_auth_replace_redirect_location(HttpProxy *self, std::string &html_form, const std::string &redirect_location)
{
  std::string search_string {"\"redirect_location\" value=\"\""};
  std::size_t found = html_form.find(search_string);
  if (found != std::string::npos)
    {
      std::string request_url(redirect_location);
      if (request_url.empty())
        {
          if (self->remote_server->len)
            request_url = std::string(self->super.tls_opts.ssl_sessions[EP_CLIENT] ? "https" : "http") +
                          "://" + self->remote_server->str;
          request_url.append(self->request_url->str);
        }
      html_form.insert(found+search_string.length()-1, request_url);
    }
}

static void
http_auth_update_accept_credit_until(HttpProxy *self, ZorpAuthInfo *auth_info, const time_t &now)
{
  G_LOCK(auth_mutex);

  if (self->max_auth_time > 0)
    auth_info->accept_credit_until = now + self->max_auth_time;

  G_UNLOCK(auth_mutex);
}

static void
http_set_response(HttpProxy *self, int error_code, unsigned int error_status)
{
  self->error_code = error_code;
  self->error_status = error_status;
}

static void
http_add_authorization_hdr(HttpProxy *self, ZorpAuthInfo *auth_info)
{
  if (self->transparent_mode && (self->auth_by_form || self->auth_by_cookie))
    {
      z_proxy_log(self, HTTP_POLICY, 4, "Relaying Basic authentication after successful client "
                                        "authentication; username='%s'", auth_info->username);
      http_add_header(&self->headers[EP_CLIENT], "Authorization", strlen("Authorization"),
                      self->auth_header_value->str, self->auth_header_value->len);
    }
  else if (!self->transparent_mode && self->auth_by_cookie)
    {
      z_proxy_log(self, HTTP_POLICY, 4, "Relaying Basic proxy-authentication after successful client "
                                        "authentication; username='%s'", auth_info->username);
      http_add_header(&self->headers[EP_CLIENT], "Proxy-Authorization", strlen("Proxy-Authorization"),
                      self->auth_header_value->str, self->auth_header_value->len);
    }
}

static gboolean
http_process_request(HttpProxy *self)
{
  HttpHeader *host_header = nullptr, *authorization_header = nullptr;
  const gchar *reason;
  static time_t prev_cleanup = 0;
  ZorpAuthInfo *auth_info;

  /* The variable below is to keep the code simple.
     There are some situation when Zorp should put
     a Set-Cookie header into the answer. But the
     condition is not too simple. And the good place
     when all the condititons could evaluate esaily is
     too early to get server domain name which is
     needed for the header. So the header should be set
     in a latter place. This variable is to know that this
     should happen. */
  gboolean need_cookie_header = FALSE;
  gchar client_key[512] = "";

  z_proxy_enter(self);

  if (self->proto_version[EP_CLIENT] > 0x0100)
    self->connection_mode = HTTP_CONNECTION_KEEPALIVE;
  else
    self->connection_mode = HTTP_CONNECTION_CLOSE;

  if (http_lookup_header(&self->headers[EP_CLIENT], "Host", &host_header))
    g_string_assign(self->remote_server, host_header->value->str);
  else
    g_string_truncate(self->remote_server, 0);

  // please mind, that auth can be set to NULL in case of keep-alive connections further requests!
  if (self->auth)
    {
      if (self->proto_version[EP_CLIENT] >= 0x0100)
        {
          ZSockAddr *client_addr;
          struct in_addr c_addr;
          time_t now = time(NULL);
          gchar buf[4096];

          bool basic_auth_header_exists = http_lookup_header(&self->headers[EP_CLIENT], "Authorization", &authorization_header);
          bool do_basic_auth = basic_auth_header_exists || !self->auth_by_form;

          if (self->auth_by_cookie || !do_basic_auth)
            {
              if (!http_get_client_info(self, client_key, sizeof(client_key)))
                g_assert_not_reached();
            }
          else if (basic_auth_header_exists)
            {
              z_proxy_get_addresses(&self->super, NULL, &client_addr, NULL, NULL, NULL, NULL);
              c_addr = z_sockaddr_inet_get_address(client_addr);
              z_sockaddr_unref(client_addr);
              z_inet_ntoa(client_key, INET_ADDRSTRLEN, c_addr);
              strncat(client_key, authorization_header->value->str, authorization_header->value->len);
            }

          G_LOCK(auth_mutex);

          if (now > prev_cleanup + (2 * MAX(self->max_auth_time, self->auth_cache_time)))
            {
              g_hash_table_foreach_remove(auth_hash, http_auth_is_expired,
                                          GUINT_TO_POINTER(now - (2 * MAX(self->max_auth_time, self->auth_cache_time))));
              prev_cleanup = now;
            }

          auth_info = static_cast<ZorpAuthInfo *>(g_hash_table_lookup(auth_hash, client_key));

          bool auth_info_should_be_freed = false;
          if (auth_info == NULL)
            {
              auth_info = g_new0(ZorpAuthInfo, 1);
              auth_info->created_at = now;
              auth_info_should_be_freed = true;
              if (client_key[0] != '\0')
                {
                  g_hash_table_insert(auth_hash, g_strdup(client_key), auth_info);
                  auth_info_should_be_freed = false;
                }
            }

          bool is_auth_cache_not_expired = self->auth_cache_time > 0 &&
                                           self->auth_cache_time + auth_info->last_auth_time > now;

          bool user_authenticated = is_auth_cache_not_expired &&
                                    z_proxy_user_authenticated_default(&self->super, auth_info->username,
                                                                       const_cast<const gchar **>(auth_info->groups));

          z_proxy_log(self, HTTP_DEBUG, 7, "User authentication cache state; entity='%s', state='%d'", auth_info->username, is_auth_cache_not_expired);

          if (user_authenticated)
            {
              if (self->auth_cache_update)
                {
                  auth_info->last_auth_time = now;
                }

              if (self->auth_forward && auth_info->basic_auth_creds)
                {
                  g_string_assign(self->auth_header_value, auth_info->basic_auth_creds);

                  if (self->auth_by_cookie || (self->auth_by_form && !basic_auth_header_exists))
                    {
                      http_add_authorization_hdr(self, auth_info);
                    }
                }
              G_UNLOCK(auth_mutex);
            }
          else
            {
              /* authentication is required */
              g_string_truncate(self->auth_header_value, 0);
              G_UNLOCK(auth_mutex);

              bool is_auth_time_window_expired = auth_info->accept_credit_until > 0 && auth_info->accept_credit_until < now;
              if (self->transparent_mode)
                {
                  std::string redirect_location;
                  if (!do_basic_auth && (is_auth_time_window_expired || !http_get_form_auth(self, auth_info, redirect_location)))
                    {
                      http_auth_update_accept_credit_until(self, auth_info, now);
                      http_set_response(self, HTTP_MSG_OK, 200);

                      std::string authform_file_path;
                      if (self->login_page_path->len > 0)
                        authform_file_path = self->login_page_path->str;
                      else
                        authform_file_path = http_error_file_path(self, "authform.html");

                      gchar *authform_file = z_error_loader_format_file(authform_file_path.c_str(), "", Z_EF_ESCAPE_HTML, NULL, NULL);
                      if (authform_file)
                        {
                          std::string html_form {authform_file};
                          http_form_auth_replace_redirect_location(self, html_form, redirect_location);
                          g_string_assign(self->custom_response_body, html_form.c_str());
                          g_free(authform_file);
                          self->send_custom_response = TRUE;
                        }
                      else
                        {
                          self->error_code = HTTP_MSG_IO_ERROR;
                        }
                      z_proxy_return(self, FALSE);
                    }
                  else if (do_basic_auth && (is_auth_time_window_expired || !basic_auth_header_exists || !http_process_auth_info(self, authorization_header, auth_info)))
                    {
                      http_auth_update_accept_credit_until(self, auth_info, now);
                      http_set_response(self, HTTP_MSG_AUTH_REQUIRED, 401);
                      g_string_sprintf(self->error_msg, "Authentication is required.");
                      g_string_sprintfa(self->error_headers, "WWW-Authenticate: %s\r\n",
                                        http_process_create_realm(self, now, buf, sizeof(buf)));
                      z_proxy_return(self, FALSE);
                    }
                }
              else if (is_auth_time_window_expired ||
                       !http_lookup_header(&self->headers[EP_CLIENT], "Proxy-Authorization", &authorization_header) ||
                       !http_process_auth_info(self, authorization_header, auth_info))
                {
                  if (self->auth_by_form)
                    {
                      z_proxy_log(self, HTTP_POLICY, 1, "Configuration error, form-based authentication "
                                                        "is not supported in non-transparent mode; "
                                                        "auth_by_form='%s', transparent_mode='%s'",
                                                        self->auth_by_form ? "TRUE" : "FALSE",
                                                        self->transparent_mode ? "TRUE" : "FALSE");
                      self->error_code = HTTP_MSG_POLICY_SYNTAX;
                      z_proxy_return(self, FALSE);
                    }

                  http_auth_update_accept_credit_until(self, auth_info, now);
                  http_set_response(self, HTTP_MSG_AUTH_REQUIRED, 407);
                  g_string_sprintf(self->error_msg, "Authentication is required.");
                  g_string_sprintfa(self->error_headers, "Proxy-Authenticate: %s\r\n",
                                    http_process_create_realm(self, now, buf, sizeof(buf)));
                  z_proxy_return(self, FALSE);
                }

              if (authorization_header)
                g_string_assign(self->auth_header_value, authorization_header->value->str);

              if (self->auth_by_cookie || !do_basic_auth)
                need_cookie_header = TRUE;
            }
          if (auth_info_should_be_freed)
            http_auth_destroy(auth_info);
        }
      else
        {
          z_proxy_log(self, HTTP_POLICY, 2, "Authentication required, but client requested HTTP/0.9 which does not support authentication;");
          z_proxy_return(self, FALSE);
        }
    }

  if (self->request_flags & HTTP_REQ_FLG_CONNECT)
    {
      if (self->proto_version[EP_CLIENT] >= 0x0100)
        {
          self->request_type = HTTP_REQTYPE_PROXY;
          z_proxy_return(self, TRUE);
        }

      self->error_code = HTTP_MSG_CLIENT_SYNTAX;
      g_string_sprintf(self->error_info, "CONNECT method requires HTTP/1.0 or later");
      /*LOG
        This message indicates that the client sent a CONNECT method
        request, but it is only supported for HTTP/1.0 or later.
      */
      z_proxy_log(self, HTTP_VIOLATION, 1, "CONNECT method without version specification;");
      z_proxy_return(self, FALSE);
    }

  self->request_type = http_get_request_type(self);
  http_process_connection_headers(self);

  if (self->connection_hdr)
    {
      gint connection_mode;

      http_process_connection_header_tokens(&self->headers[EP_CLIENT], self->connection_hdr);

      /* connection_mode overridden by connection header */
      connection_mode = http_parse_connection_hdr_value(self, self->connection_hdr);

      if (connection_mode != HTTP_CONNECTION_UNKNOWN)
        self->connection_mode = connection_mode;
    }

  if (self->transparent_mode &&
      ((self->request_type == HTTP_REQTYPE_PROXY && !self->permit_proxy_requests) ||
       (self->request_type == HTTP_REQTYPE_SERVER && !self->permit_server_requests)))
    {
      /* */
      self->error_code = HTTP_MSG_POLICY_VIOLATION;
      g_string_sprintf(self->error_info, "%s requests not permitted in transparent mode.",
                       self->request_type == HTTP_REQTYPE_SERVER ? "server" : "proxy");
      /*LOG
        This message indicates that the client sent the given type request,
        which is not permitted by the policy. Check the
        permit_proxy_requests and the permit_server_requests attributes.
      */
      z_proxy_log(self, HTTP_POLICY, 2,
                  "This request type is not permitted in transparent mode; request_type='%s'",
                  self->request_type == HTTP_REQTYPE_SERVER ? "server" : "proxy");
      z_proxy_return(self, FALSE);
    }

  if (self->transparent_mode)
    {
      if (self->request_url->str[0] == '/')
        {
          gchar buf[self->remote_server->len + 32];

          /* no protocol description */
          if (!self->remote_server->len)
            {
              if (!self->require_host_header)
                {
                  /* no host header */
                  /*LOG
                    This message indicates that no Host header was sent by
                    the client. As the content of the host header is used
                    to reconstruct the requested URL, the request_url
                    attribute will refer to a host named 'unknown'.
                  */
                  z_proxy_log(self, HTTP_VIOLATION, 4, "No host header in transparent request, 'unknown' is used instead;");
                  g_string_assign(self->remote_server, "unknown");
                }
              else
                {
                  self->error_code = HTTP_MSG_CLIENT_SYNTAX;

                  if (self->proto_version[EP_CLIENT] < 0x0100)
                    {
                      g_string_sprintf(self->error_info, "'Host:' header is required, and HTTP/0.9 can't transfer headers.");
                      /*LOG
                        This message indicates that an HTTP/0.9 request was
                        sent by the client, and Host header is required by
                        the policy, but HTTP/0.9 does not support headers.
                        Check the require_host_header attribute.
                      */
                      z_proxy_log(self, HTTP_POLICY, 2, "'Host:' header is required, and HTTP/0.9 can't transfer headers;");
                    }
                  else
                    {
                      g_string_sprintf(self->error_info, "No 'Host:' header in request, and policy requires this.");
                      /*LOG
                        This message indicates that no Host header was sent
                        by the client, but it was required by the policy.
                        Check the require_host_header attribute.
                      */
                      z_proxy_log(self, HTTP_POLICY, 2, "No 'Host:' header in request, and policy requires this;");
                    }

                  z_proxy_return(self, FALSE);
                }
            }

          g_snprintf(buf, sizeof(buf), "%s://%s", self->super.tls_opts.ssl_sessions[EP_CLIENT] ? "https" : "http", self->remote_server->str);
          g_string_prepend(self->request_url, buf);
        }
    }

  if (!http_parse_url(&self->request_url_parts, self->permit_unicode_url,
                      self->permit_invalid_hex_escape, FALSE, self->request_url->str, &reason))
    {
      /* invalid URL */
      self->error_code = HTTP_MSG_INVALID_URL;
      g_string_sprintf(self->error_info, "Badly formatted url: %s", self->request_url->str);
      /*LOG
        This message indicates that there was an error parsing an already
        canonicalized URL.  Please report this event to the BalaSys
	Development Team (at devel@balasys.hu)
      */
      z_proxy_log(self, HTTP_ERROR, 1, "Error parsing URL; url='%s', reason='%s'", self->request_url->str, reason);
      z_proxy_return(self, FALSE);
    }

  if (!http_format_url(&self->request_url_parts, self->request_url, TRUE, self->permit_unicode_url, TRUE, &reason))
    {
      self->error_code = HTTP_MSG_INVALID_URL;
      g_string_sprintf(self->error_info, "Error canonicalizing url (%s): %s", reason, self->request_url->str);
      /*LOG
        This message indicates that there was an error parsing an already
        canonicalized URL.  Please report this event to the BalaSys
	Development Team (at devel@balasys.hu)
      */
      z_proxy_log(self, HTTP_ERROR, 1, "Error parsing URL; url='%s', reason='%s'", self->request_url->str, reason);
      z_proxy_return(self, FALSE);
    }

  if (!HttpUrlFilter::get_instance().filter_url(self, self->request_url->str, self->request_url_parts))
    return false;

  self->remote_port = self->request_url_parts.port;

  if (need_cookie_header)
    {
      gchar *hostname = self->request_url_parts.host->str;
      gchar *startpos = hostname;
      gchar *dotpos = strchr(startpos, '.');
      gchar *nextdotpos = NULL;

      if (dotpos != NULL)
        nextdotpos = strchr(dotpos + 1, '.');

      while (nextdotpos != NULL)
        {
          startpos = dotpos;
          dotpos = nextdotpos;
          nextdotpos = strchr(dotpos + 1, '.');
        }

      std::string append_cookie { HttpProxy::zorp_realm_cookie_name + "=" + client_key + "; path=/; domain=" + startpos};
      if (self->auth_by_form)
        {
          g_string_append_printf(self->error_headers, "Set-Cookie: %s\r\n", append_cookie.c_str());
          z_proxy_return(self, FALSE);
        }
      else
        {
          self->append_cookie = g_string_sized_new(32);
          g_string_assign(self->append_cookie, append_cookie.c_str());
        }
    }

  z_proxy_return(self, TRUE);
}

static gboolean
http_process_filtered_request(HttpProxy *self)
{
  if ((self->request_flags & HTTP_REQ_FLG_CONNECT))
    {
      self->server_protocol = HTTP_PROTO_HTTP;
    }
  else if (http_parent_proxy_enabled(self) &&
           (strcasecmp(self->request_url_parts.scheme->str, "http") == 0 ||
            strcasecmp(self->request_url_parts.scheme->str, "ftp") == 0 ||
            strcasecmp(self->request_url_parts.scheme->str, "cache_object") == 0))
    {
      self->server_protocol = HTTP_PROTO_HTTP;
    }
  else if (!http_parent_proxy_enabled(self) && strcasecmp(self->request_url_parts.scheme->str, "ftp") == 0)
    {
      if (self->permit_ftp_over_http)
        {
          self->server_protocol = HTTP_PROTO_FTP;
        }
      else
        {
          /*LOG
            This message indicates that a client tried to use FTP over HTTP
            which is not allowed by default. Either set a parent proxy or
            enable the permit_ftp_over_http attribute.
          */
          z_proxy_log(self, HTTP_POLICY, 2, "Client attempted to use FTP over HTTP, which is currently disabled;");
          self->error_code = HTTP_MSG_CLIENT_SYNTAX;
          z_proxy_return(self, FALSE);
        }
    }
  else if (!http_parent_proxy_enabled(self) &&
           strcasecmp(self->request_url_parts.scheme->str, "http") == 0)
    {
      self->server_protocol = HTTP_PROTO_HTTP;
    }
  else if (!http_parent_proxy_enabled(self) &&
           strcasecmp(self->request_url_parts.scheme->str, "https") == 0)
    {
      self->server_protocol = HTTP_PROTO_HTTPS;
    }
  else
    {
      /* unsupported protocol */
      self->error_code = HTTP_MSG_CLIENT_SYNTAX;
      g_string_sprintf(self->error_info, "Unsupported scheme: %s", self->request_url_parts.scheme->str);
      /*LOG
        This message indicates that the requested URL refers to an
        unsupported protocol scheme. Zorp currently knows about http and
        cache_object protocols, and can support the ftp protocol
        if a parent_proxy supporting ftp over http tunneling is present.
      */
      z_proxy_log(self, HTTP_ERROR, 3, "Unsupported scheme in URL; proto='%s'", self->request_url_parts.scheme->str);
      z_proxy_return(self, FALSE);
    }

  if (self->request_url_parts.host->len > self->max_hostname_length)
    {
      self->error_code = HTTP_MSG_CLIENT_SYNTAX;
      g_string_sprintf(self->error_info, "Too long hostname in URL: %s", self->request_url_parts.host->str);
      /*LOG
        This message indicates that the HTTP request was rejected because
        the hostname part in the URL was too long. You can increase the permitted
        limit by changing the max_hostname_length attribute.
      */
      z_proxy_log(self, HTTP_POLICY, 2, "Too long hostname in URL; host='%s', length='%" G_GSIZE_FORMAT "', max_hostname_length='%d'",
                  self->request_url_parts.host->str, self->request_url_parts.host->len, self->max_hostname_length);
      z_proxy_return(self, FALSE);
    }

  if (self->remote_port == 0)
    self->remote_port = http_get_default_port_for_protocol(self);

  if (!(self->request_flags & HTTP_REQ_FLG_CONNECT))
    http_rewrite_host_header(self, self->request_url_parts.host->str, self->request_url_parts.host->len, self->remote_port, self->server_protocol);

  if (http_parent_proxy_enabled(self))
    {
      self->remote_port = self->parent_proxy_port;
      g_string_assign(self->remote_server, self->parent_proxy->str);
    }
  else
    {
      g_string_assign(self->remote_server, self->request_url_parts.host->str);
    }

  /*LOG
    This is an accounting message that reports the requested method and URL.
  */
  z_proxy_log(self, HTTP_ACCOUNTING, 4, "Accounting; command='%s', url='%s'", self->request_method->str, self->request_url->str);
  z_proxy_return(self, TRUE);
}

/* FIXME: this code should be converted into an explicit referral to the
 * modified headers, e.g. instead of looping over all the headers, lookup
 * the necessary headers using http_lookup_header and modify the returned
 * values */
static guint
http_request_filter_headers(HttpProxy *self, GString *name, GString *value)
{
  gint res = HTTP_HDR_ACCEPT;

  z_proxy_enter(self);

  switch (self->request_type)
    {
    case HTTP_REQTYPE_SERVER:

      /* if we have a parent proxy, Connection -> Proxy-Connection
       * otherwise leave it as is
       */
      if (strcasecmp(name->str, "Connection") == 0)
        {
          if (http_parent_proxy_enabled(self))
            g_string_assign(name, "Proxy-Connection");

          http_assign_connection_hdr_value(self, value);
        }
      else if (strcasecmp(name->str, "Authorization") == 0)
        {
          if (self->auth)
            {
              /* if inband authentication was performed, drop the
               * authentication header unless forwarding was explicitly
               * requested */
              if (self->auth_forward)
                {
                  g_string_assign(value, self->auth_header_value->str);

                  /* if the upstream is a proxy, forward it as a
                   * Proxy-Authorization header */

                  if (http_parent_proxy_enabled(self))
                    g_string_assign(name, "Proxy-Authorization");
                }
              else
                {
                  res = HTTP_HDR_DROP;
                }
            }
        }

      break;

    case HTTP_REQTYPE_PROXY:

      /* if we have a parent proxy leave it as is
       * otherwise Proxy-Connection -> Connection
       */
      if (strcasecmp(name->str, "Proxy-Connection") == 0)
        {
          if (http_parent_proxy_enabled(self) == 0)
            g_string_assign(name, "Connection");

          http_assign_connection_hdr_value(self, value);
        }
      else if (strcasecmp(name->str, "Proxy-Authorization") == 0)
        {
          if (self->auth)
            {
              /* if inband authentication was performed, drop the
               * authentication header unless forwarding was explicitly
               * requested */
              if (self->auth_forward)
                {
                  g_string_assign(value, self->auth_header_value->str);

                  /* if the upstream is not a proxy, forward it as a
                   * Authorization header */
                  if (!http_parent_proxy_enabled(self))
                    g_string_assign(name, "Authorization");
                }
              else
                {
                  res = HTTP_HDR_DROP;
                }
            }
        }

      break;
    }

  z_proxy_return(self, res);
}

static gboolean
http_filter_request(HttpProxy *self)
{
  ZPolicyObj *f;
  gint rc;

  z_proxy_enter(self);
  f = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->request_method_policy, self->request_method->str));

  if (!f)
    f = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->request_method_policy, "*"));

  if (f)
    {
      ZPolicyObj *handler, *res;
      gchar *errmsg;
      guint filter_type;

      z_policy_lock(self->super.thread);

      if (!z_policy_tuple_get_verdict(f, &filter_type))
        {
          /*LOG
            This message indicates that the request hash contains an invalid
            item for the given request method. Check your Zorp
            configuration.
          */
          z_proxy_log(self, HTTP_POLICY, 1, "Invalid item in request hash; method='%s'", self->request_method->str);
          z_proxy_report_invalid_policy(&(self->super));
          z_policy_unlock(self->super.thread);
          z_proxy_return(self, FALSE);

        }

      z_policy_unlock(self->super.thread);
      g_string_sprintf(self->error_info, "Method %s denied by policy", self->request_method->str);

      switch (filter_type)
        {
        case HTTP_REQ_POLICY:
          z_policy_lock(self->super.thread);

          if (!z_policy_var_parse(f, "(iO)", &filter_type, &handler))
            {
              /*LOG
                This message indicates that the request hash contains an
                invalid POLICY tuple for the given request method.  It
                should contain a valid call-back function in the tuple.
              */
              z_proxy_log(self, HTTP_POLICY, 1, "Error parsing HTTP_REQ_POLICY tuple in request hash; method='%s'", self->request_method->str);
              z_proxy_report_invalid_policy(&(self->super));
              z_policy_unlock(self->super.thread);
              z_proxy_return(self, FALSE);
            }

          res = z_policy_call_object(handler,
                                     z_policy_var_build("(sss)",
                                                        self->request_method->str, self->request_url->str, self->request_version),
                                     self->super.session_id);

          if (!res || !z_policy_var_parse(res, "i", &rc))
            {
              rc = HTTP_REQ_REJECT;
              g_string_assign(self->error_info, "Error in policy handler, or returned value not integer;");
              z_proxy_report_policy_abort(&(self->super));
            }

          z_policy_var_unref(res);
          z_policy_unlock(self->super.thread);
          break;

        case HTTP_REQ_REJECT:
          errmsg = NULL;
          z_policy_lock(self->super.thread);

          if (!z_policy_var_parse_tuple(f, "i|s", &filter_type, &errmsg))
            {
              /*LOG
                This message indicates that the request hash contains an
                invalid REJECT tuple for the given request method.  It
                should contain an error message, which is sent back to the
                client.
              */
              z_proxy_log(self, HTTP_POLICY, 1, "Error parsing HTTP_REQ_REJECT in request hash; req='%s'", self->request_method->str);
              z_proxy_report_invalid_policy(&(self->super));
              z_policy_unlock(self->super.thread);
              z_proxy_return(self, FALSE);
            }

          z_policy_unlock(self->super.thread);

          if (errmsg)
            g_string_assign(self->error_info, errmsg);

          /* fallthrough */

        case HTTP_REQ_ACCEPT:
        case HTTP_REQ_DENY:
        case HTTP_REQ_ABORT:
          /* dropped command */
          rc = filter_type;
          break;

        default:
          /*LOG
            This message indicates that the request hash contains an invalid
            action for the given request method.  Check your Zorp
            configuration.
          */
          z_proxy_log(self, HTTP_POLICY, 1, "Unknown request hash item; req='%s'", self->request_method->str);
          z_proxy_return(self, FALSE);
        }

      switch (rc)
        {
        case HTTP_REQ_ACCEPT:
          g_string_truncate(self->error_info, 0);
          break;

        case HTTP_REQ_CUSTOM_RESPONSE:
          /*LOG
            This log message indicates that the policy requested a custom response to be sent to the client.
          */
          z_proxy_log(self, HTTP_POLICY, 6, "Policy requested to send custom response; req='%s'", self->request_method->str);
          self->send_custom_response = TRUE;
          z_proxy_return(self, TRUE);

        default:
          /*LOG
            This log message indicates that the specified HTTP request was not permitted by your policy.
          */
          z_proxy_log(self, HTTP_POLICY, 2, "Request not permitted by policy; req='%s'", self->request_method->str);
          if (self->error_code == HTTP_MSG_NOT_ASSIGNED)
            self->error_code = HTTP_MSG_POLICY_VIOLATION;
          z_proxy_return(self, FALSE);
        }

      if (self->proto_version[EP_CLIENT] >= 0x0100)
        {
          if (!http_filter_headers(self, EP_CLIENT, http_request_filter_headers))
            z_proxy_return(self, FALSE);
        }

      z_proxy_return(self, TRUE);
    }

  self->error_code = HTTP_MSG_POLICY_VIOLATION;
  g_string_sprintf(self->error_info, "Method %s denied by policy", self->request_method->str);
  /*LOG
    This log message indicates that the specified HTTP request was not permitted by your policy.
  */
  z_proxy_log(self, HTTP_POLICY, 2, "Request not permitted by policy; req='%s'", self->request_method->str);
  z_proxy_return(self, FALSE);
}

static gboolean
http_server_stream_ready(HttpProxy *self)
{
  gboolean res = FALSE;

  z_proxy_enter(self);

  if (self->super.endpoints[EP_SERVER])
    {
      GIOStatus rc;
      gchar buf[1];
      gsize bytes_read;
      ZStream *stream = self->super.endpoints[EP_SERVER];

      z_stream_set_nonblock(stream, TRUE);
      rc = z_stream_read(stream, &buf, sizeof(buf), &bytes_read, NULL);
      z_stream_set_nonblock(stream, FALSE);

      if (rc == G_IO_STATUS_NORMAL || rc == G_IO_STATUS_AGAIN)
        {
          res = TRUE;

          if (bytes_read > 0 && !z_stream_unget(stream, buf, bytes_read, NULL))
            {
              z_proxy_log(self, HTTP_ERROR, 2, "Error while checking if server stream is ready, buffer full");
              res = FALSE;
            }
        }
    }

  z_proxy_return(self, res);
}

gboolean
http_connect_server(HttpProxy *self)
{
  z_proxy_enter(self);

  if (!self->super.endpoints[EP_SERVER] ||
      !http_server_stream_ready(self) ||
      (!self->transparent_mode &&
       (strcasecmp(self->remote_server->str, self->connected_server->str) != 0 ||
        self->remote_port != self->connected_port)) ||
      self->force_reconnect)
    {
      gboolean success = FALSE;

      self->force_reconnect = FALSE;

      if (self->super.endpoints[EP_SERVER])
        {
          z_stream_shutdown(self->super.endpoints[EP_SERVER], SHUT_RDWR, NULL);
          z_stream_close(self->super.endpoints[EP_SERVER], NULL);
          z_stream_unref(self->super.endpoints[EP_SERVER]);
          self->super.endpoints[EP_SERVER] = NULL;

          z_proxy_ssl_clear_session(&self->super, EP_SERVER);
        }

      g_string_sprintf(self->error_info, "Error establishing connection to %s", self->remote_server->str);

      if (http_parent_proxy_enabled(self))
        {
          success = z_proxy_connect_server(&self->super, self->parent_proxy->str, self->parent_proxy_port);
        }
      else if (self->transparent_mode && self->use_default_port_in_transparent_mode)
        {
          success = z_proxy_connect_server(&self->super, self->remote_server->str, http_get_default_port_for_protocol(self));
        }
      else if (z_port_enabled(self->target_port_range->str, self->remote_port))
        {
          success = z_proxy_connect_server(&self->super, self->remote_server->str, self->remote_port);
        }
      else
        {
          /*LOG
            This message indicates that the proxy did not allow
            addressing the specified port as the target_port_range
            attribute does not allow it.
          */
          z_proxy_log(self, HTTP_VIOLATION, 2, "Connecting to this port is prohibited by policy; host='%s', port='%d'", self->remote_server->str, self->remote_port);
          g_string_sprintf(self->error_info, "Connecting to port %d is prohibited by policy.", self->remote_port);
          success = FALSE;
        }

      if (!success)
        {
          /* error connecting to server */
          self->error_code = HTTP_MSG_CONNECT_ERROR;
          self->error_status = 502;
          /* connect_server already logged */
          z_proxy_return(self, FALSE);
        }

      g_string_assign(self->connected_server, self->remote_server->str);
      self->connected_port = self->remote_port;
    }

  if (!http_server_stream_is_initialized(self)
      && !http_server_stream_init(self))
    {
      /* should never happen */
      /*LOG
        This message indicates that initializing the server stream
        failed. Please report this event to the BalaSys Development Team (at
        devel@balasys.hu).
      */
      z_proxy_log(self, HTTP_ERROR, 1, "Internal error initializing server stream;");
      z_proxy_return(self, FALSE);
    }

  z_proxy_return(self, TRUE);
}

static gboolean
http_copy_request(HttpProxy *self)
{
  ZStream *blob_stream = NULL;

  z_proxy_enter(self);

  if (!http_connect_server(self))
    z_proxy_return(self, FALSE); /* connect_server already logs */

  if (!http_check_name(self))
    {
      z_proxy_return(self, FALSE);
    }

  if (self->request_data_stored && self->request_data && self->request_data->size > 0)
    {
      gchar session_id[MAX_SESSION_ID];

      g_snprintf(session_id, sizeof(session_id), "%s/post", self->super.session_id);
      blob_stream = z_stream_blob_new(self->request_data, session_id);
      blob_stream->timeout = -1;
    }

  if (!http_data_transfer(self, blob_stream ? HTTP_TRANSFER_FROM_BLOB : HTTP_TRANSFER_NORMAL, EP_CLIENT, blob_stream ? blob_stream : self->super.endpoints[EP_CLIENT], EP_SERVER, self->super.endpoints[EP_SERVER], FALSE, FALSE, http_format_request))
    {
      /* http_data_transfer already logs */
      z_stream_unref(blob_stream);
      z_proxy_return(self, FALSE);
    }

  z_stream_unref(blob_stream);
  z_proxy_return(self, TRUE);
}

static gboolean
http_fetch_response(HttpProxy *self)
{
  gchar *line;
  gsize line_length, br;
  GIOStatus res;
  gchar status[4];

  z_proxy_enter(self);
  /* FIXME: this can probably be removed as http_fetch_header does this */
  http_clear_headers(&self->headers[EP_SERVER]);
  self->response[0] = 0;
  self->response_code = -1;

  if (self->proto_version[EP_CLIENT] < 0x0100)
    {
      self->proto_version[EP_SERVER] = 0x0009;
      z_proxy_return(self, TRUE);
    }

  while (self->response_code == -1 || self->response_code == 100 || self->response_code == 102)
    {
      self->super.endpoints[EP_SERVER]->timeout = self->timeout_response;
      res = z_stream_read_chunk(self->super.endpoints[EP_SERVER], status, sizeof(status), &br, NULL);
      self->super.endpoints[EP_SERVER]->timeout = self->timeout;

      if (res != G_IO_STATUS_NORMAL)
        {
          /* the server closed our connection */
          self->error_code = HTTP_MSG_OK;
          z_proxy_return(self, FALSE);
        }

      if (!z_stream_unget(self->super.endpoints[EP_SERVER], status, br, NULL))
        {
          /* error falling back to 0.9 */
          /*LOG
            This message indicates that Zorp was unable to enable HTTP/0.9
            compatibility mode, due to the full buffer.  If you experience
            this problem many times, please contact your Zorp support.
          */
          z_proxy_log(self, HTTP_ERROR, 2, "Error in HTTP/0.9 compatibility code, line buffer full;");
          z_proxy_return(self, FALSE);
        }

      if (br == 4 && memcmp(status, "HTTP", 4) == 0)
        {
          res = z_stream_line_get(self->super.endpoints[EP_SERVER], &line, &line_length, NULL);

          if (res != G_IO_STATUS_NORMAL)
            {
              self->error_code = HTTP_MSG_OK;
              z_proxy_return(self, FALSE);
            }
        }
      else if (self->permit_http09_responses)
        {
          self->proto_version[EP_SERVER] = 0x0009;
          z_proxy_return(self, TRUE);
        }
      else
        {
          /* HTTP/0.9 is not permitted by policy */
          g_string_assign(self->error_info, "Server falled back to HTTP/0.9 which is prohibited by policy.");
          /*LOG
            This message indicates that the server sent back HTTP/0.9
            response, which is prohibited by the policy.  It is likely a
            buggy or old server. Check the permit_http09_responses
            attribute.
          */
          z_proxy_log(self, HTTP_POLICY, 2, "Server falled back to HTTP/0.9 which is prohibited by policy;");
          z_proxy_return(self, FALSE);
        }

      if (!http_split_response(self, line, line_length))
        {
          /*LOG
            This message indicates the the HTTP status line returned by the
            server was invalid.
          */
          z_proxy_log(self, HTTP_VIOLATION, 1, "Invalid HTTP response heading; line='%.*s'", (gint)line_length, line);
          g_string_assign(self->error_info, "Invalid HTTP response heading");
          z_proxy_return(self, FALSE);
        }

      self->response_flags = http_proto_response_lookup(self->response);

      if (!http_parse_version(self, EP_SERVER, self->response_version))
        {
          g_string_sprintf(self->error_info, "Invalid HTTP version in response (%.*s)", (gint) line_length, line);
          /*LOG
            This message indicates that the server sent the response with an
            invalid HTTP version.  It is likely that the server is buggy.
          */
          z_proxy_log(self, HTTP_VIOLATION, 1, "Error parsing response version; line='%.*s'", (gint) line_length, line);
          z_proxy_return(self, FALSE);
        }

      if (!http_fetch_headers(self, EP_SERVER))
        {
          g_string_assign(self->error_info, "Invalid headers received in response");
          z_proxy_return(self, FALSE);
        }

      if (self->append_cookie)
        {
          http_add_header(&self->headers[EP_SERVER], "Set-Cookie", strlen("Set-Cookie"),
                          self->append_cookie->str, self->append_cookie->len);
          g_string_free(self->append_cookie, TRUE);
          self->append_cookie = NULL;
        }
    }

  z_proxy_return(self, TRUE);
}

static gboolean
http_process_response(HttpProxy *self)
{
  HttpHeader *pconn_hdr = NULL, *conn_hdr = NULL;

  z_proxy_enter(self);

  /* previously set by http_parse_version */
  switch (self->proto_version[EP_SERVER])
    {
    case 0x0009:
      g_strlcpy(self->response, "200", sizeof(self->response_code));
      self->response_code = 200;
      self->response_flags = 0;
      self->connection_mode = HTTP_CONNECTION_CLOSE;
      self->server_connection_mode = HTTP_CONNECTION_CLOSE;
      z_proxy_return(self, TRUE);

    case 0x0100:
      self->server_connection_mode = HTTP_CONNECTION_CLOSE;
      break;

    case 0x0101:
      self->server_connection_mode = HTTP_CONNECTION_KEEPALIVE;
      break;

    default:
      /*LOG
        This message indicates that the server sent an unsupported protocol
        version. It is likely that the server is buggy.
      */
      z_proxy_log(self, HTTP_VIOLATION, 1, "Unsupported protocol version; version='0x%04x'", self->proto_version[EP_SERVER]);
      z_proxy_return(self, FALSE);
    }

  /* process connection header */
  self->connection_hdr = NULL;
  http_lookup_header(&self->headers[EP_SERVER], "Proxy-Connection", &pconn_hdr);
  http_lookup_header(&self->headers[EP_SERVER], "Connection", &conn_hdr);

  if ((http_parent_proxy_enabled(self) && pconn_hdr) || conn_hdr)
    {
      /* override default */
      if (http_parent_proxy_enabled(self) && pconn_hdr)
        {
          self->connection_hdr = pconn_hdr;

          if (conn_hdr)
            conn_hdr->present = FALSE;
        }
      else
        {
          self->connection_hdr = conn_hdr;

          if (pconn_hdr)
            pconn_hdr->present = FALSE;
        }

      if (self->connection_mode == HTTP_CONNECTION_KEEPALIVE &&
          http_parse_connection_hdr_value(self, self->connection_hdr) != HTTP_CONNECTION_CLOSE)
        self->server_connection_mode = HTTP_CONNECTION_KEEPALIVE;
      else
        self->server_connection_mode = HTTP_CONNECTION_CLOSE;
    }
  else
    {
      /* NOTE: there was no appropriate Connection header in the response, if it
       * is an 1.0 client the connection mode should be changed to
       * connection close regardless what the client specified in its
       * connection header.
       */
      const gchar *conn_hdr_str = http_parent_proxy_enabled(self) ? "Proxy-Connection" : "Connection";

      /* we add an appriopriate connection header just as if we received one
       * (e.g. it might be rewritten later by
       * http_response_filter_connection_header), we default to not sending
       * this new header, it will be made visible when we want to ensure
       * that our connection mode must be enforced. */
      self->connection_hdr = http_add_header(&self->headers[EP_SERVER], conn_hdr_str, strlen(conn_hdr_str), "close", 5);
      self->connection_hdr->present = FALSE;

      if (self->proto_version[EP_CLIENT] == 0x0100)
        {
          if (self->connection_mode == HTTP_CONNECTION_KEEPALIVE)
            {
              /* it is somewhat uncertain what happens when an 1.0 client
               * requests keepalive and an 1.1 server responds without a
               * connection header, resolve this uncertainity by adding a
               * connection header */
              self->connection_hdr->present = TRUE;
            }

          self->server_connection_mode = HTTP_CONNECTION_CLOSE;
        }
    }

  if (self->request_flags & HTTP_REQ_FLG_CONNECT && self->response_code == 200)
    self->server_connection_mode = HTTP_CONNECTION_CLOSE;

  if (!self->keep_persistent && self->server_connection_mode == HTTP_CONNECTION_CLOSE)
    self->connection_mode = HTTP_CONNECTION_CLOSE;

  if (self->response_flags & HTTP_RESP_FLG_STOP)
    z_proxy_return(self, FALSE); /* FIXME: not implemented */

  z_proxy_return(self, TRUE);
}

/**
 * http_fetch_buffered_data:
 * @self: HttpProxy instance
 *
 * Read all buffered data from the client up to maximum ten 4096 chunks.
 * This is needed to avoid sending RSTs to connections where the client sent
 * some unprocessed bytes (like IE 5.0 in the case of POST requests).
 **/
static void
http_fetch_buffered_data(HttpProxy *self)
{
  gchar buf[4096];
  gsize br;
  gint count = 0;

  z_stream_set_nonblock(self->super.endpoints[EP_CLIENT], TRUE);

  while (count < 10 && z_stream_read(self->super.endpoints[EP_CLIENT], buf, sizeof(buf), &br, NULL) == G_IO_STATUS_NORMAL)
    {
      count++;
    }

  z_stream_set_nonblock(self->super.endpoints[EP_CLIENT], FALSE);
}

static ZPolicyObj *
http_response_policy_get(HttpProxy *self)
{
  gchar *response_keys[2];

  response_keys[0] = self->request_method->str;
  response_keys[1] = self->response;

  return static_cast<ZPolicyObj *>(z_dim_hash_table_search(self->response_policy, 2, response_keys));
}

static gboolean
http_filter_response(HttpProxy *self)
{
  z_proxy_enter(self);

  if (self->proto_version[EP_SERVER] >= 0x0100)
    {
      ZPolicyObj *f, *res;
      gint rc;

      f = http_response_policy_get(self);

      if (f)
        {
          ZPolicyObj *handler;
          guint filter_type;
          gchar *errmsg;

          z_policy_lock(self->super.thread);

          if (!z_policy_tuple_get_verdict(f, &filter_type))
            {
              /*LOG
                This message indicates that the response hash contains an
                invalid item for the given response. Check your Zorp
                configuration.
              */
              z_proxy_log(self, HTTP_POLICY, 1, "Invalid response hash item; request='%s', response='%d'", self->request_method->str, self->response_code);
              z_proxy_report_invalid_policy(&(self->super));
              z_policy_unlock(self->super.thread);
              z_proxy_return(self, FALSE);
            }

          z_policy_unlock(self->super.thread);

          g_string_sprintf(self->error_info, "Response %d for %s denied by policy.", self->response_code, self->request_method->str);

          switch (filter_type)
            {
            case HTTP_RSP_POLICY:
              z_policy_lock(self->super.thread);

              if (!z_policy_var_parse(f, "(iO)", &filter_type, &handler))
                {
                  /*LOG
                    This message indicates that the response hash contains
                    an invalid POLICY tuple for the given response.  It
                    should contain a valid call-back function in the tuple.
                  */
                  z_proxy_log(self, HTTP_POLICY, 1,
                              "Error parsing HTTP_RSP_POLICY in response hash; request='%s', response='%d'",
                              self->request_method->str, self->response_code);
                  z_proxy_report_invalid_policy(&(self->super));
                  z_policy_unlock(self->super.thread);
                  z_proxy_return(self, FALSE);
                }

              res = z_policy_call_object(handler, z_policy_var_build("(sssi)", self->request_method->str, self->request_url->str, self->request_version, self->response_code), self->super.session_id);

              if (!z_policy_var_parse(res, "i", &rc))
                {
                  g_string_assign(self->error_info, "Error in policy handler.");
                  z_proxy_report_policy_abort(&(self->super));
                  rc = HTTP_RSP_REJECT;
                }

              z_policy_var_unref(res);
              z_policy_unlock(self->super.thread);
              break;

            case HTTP_RSP_REJECT:
              errmsg = NULL;
              z_policy_lock(self->super.thread);

              if (!z_policy_var_parse_tuple(f, "i|s", &filter_type, &errmsg))
                {
                  /*LOG
                    This message indicates that the response hash contains
                    an invalid REJECT tuple for the given response.
                    It should contain an error message, which is sent back to
                    the client.
                  */
                  z_proxy_log(self, HTTP_POLICY, 1,
                              "Error parsing HTTP_RSP_REJECT in response hash; request='%s', response='%d'",
                              self->request_method->str, self->response_code);
                  z_policy_unlock(self->super.thread);
                  z_proxy_return(self, FALSE);
                }

              z_policy_unlock(self->super.thread);

              if (errmsg)
                g_string_assign(self->error_info, errmsg);

              /* fallthrough */

            case HTTP_RSP_ACCEPT:
            case HTTP_RSP_DENY:
            case HTTP_RSP_ABORT:
              /* dropped command */
              rc = filter_type;
              break;

            default:
              /*LOG
                This message indicates that the response hash contains
                an invalid action for the given response.
                Check your Zorp configuration.
              */
              z_proxy_log(self, HTTP_POLICY, 1,
                          "Invalid response hash item; request='%s', response='%d'",
                          self->request_method->str, self->response_code);
              z_proxy_return(self, FALSE);
            }

          switch (rc)
            {
            case HTTP_RSP_ACCEPT:
              break;

            default:
            case HTTP_RSP_REJECT:
              /*LOG
                This message indicates that the status code returned by the server is
                not a permitted response code for this request.
              */
              z_proxy_log(self, HTTP_POLICY, 2, "Response not permitted by policy; req='%s', rsp='%d'", self->request_method->str, self->response_code);
              self->error_code = HTTP_MSG_POLICY_VIOLATION;
              z_proxy_return(self, FALSE);
            }

        }

      if (!http_filter_headers(self, EP_SERVER, NULL))
        z_proxy_return(self, FALSE);
    }

  z_proxy_return(self, TRUE);
}

static gboolean
http_format_response(HttpProxy *self, gboolean stacked, GString *response)
{
  if (self->proto_version[EP_SERVER] >= 0x0100)
    {
      if (!stacked)
        {
          http_flat_headers(&self->headers[EP_SERVER]);
          g_string_set_size(response, 4000);
          g_string_truncate(response, 0);

          g_string_append_const(response, "HTTP");
          g_string_append_c(response, '/');
          g_string_append_c(response, '0' + ((self->proto_version[EP_SERVER] & 0xFF00) >> 8));
          g_string_append_c(response, '.');
          g_string_append_c(response, '0' + (self->proto_version[EP_SERVER] & 0x00FF));
          g_string_append_c(response, ' ');
          g_string_append(response, self->response);
          g_string_append_c(response, ' ');
          g_string_append_gstring(response, self->response_msg);
          g_string_append_const(response, "\r\n");
          g_string_append_gstring(response, self->headers[EP_SERVER].flat);
          g_string_append_const(response, "\r\n");
        }
      else
        {
          http_flat_headers_into(&self->headers[EP_SERVER], response);
        }
    }
  else
    g_string_truncate(response, 0);

  return TRUE;
}

static gboolean
http_copy_response(HttpProxy *self)
{
  gboolean suppress_data, expect_data;

  z_proxy_enter(self);

  /* self->connection_hdr must never be NULL for server->client direction when at least HTTP/1.0 is used */
  if (self->proto_version[EP_SERVER] >= 0x0100)
    {
      g_assert(self->connection_hdr);

      if (self->connection_mode != self->server_connection_mode)
        self->connection_hdr->present = TRUE;

      if (self->connection_hdr->present)
        {
          g_string_assign(self->connection_hdr->name, self->request_type == HTTP_REQTYPE_SERVER ? "Connection" : "Proxy-Connection");
          http_assign_connection_hdr_value(self, self->connection_hdr->value);
        }
    }

  expect_data = (self->response_flags & HTTP_RESP_FLG_DONTEXPECT) == 0;
  suppress_data = (self->response_flags & HTTP_RESP_FLG_SUPPRESS) != 0 ||
    (self->request_flags & HTTP_REQ_FLG_HEAD) != 0 ||
    ((self->request_flags & HTTP_REQ_FLG_CONNECT) != 0 && self->response_code == 200);

  if (!http_data_transfer(self, HTTP_TRANSFER_NORMAL, EP_SERVER, self->super.endpoints[EP_SERVER], EP_CLIENT, self->super.endpoints[EP_CLIENT], expect_data, suppress_data, http_format_response))
    z_proxy_return(self, FALSE); /* http_data_transfer already logs */

  z_proxy_return(self, TRUE);
}

static gboolean
http_handle_connect(HttpProxy *self)
{
  /* connect is enabled here */
  guint i;
  ZPolicyObj *res;
  gboolean called;
  gchar *success, *remote_host;
  gchar *colon, *end;
  gint remote_host_len, remote_port;

  z_proxy_enter(self);
  self->connection_mode = HTTP_CONNECTION_CLOSE;
  colon = strchr(self->request_url->str, ':');

  if (colon)
    {
      remote_host = self->request_url->str;
      remote_host_len = colon - remote_host;
      remote_port = strtoul(colon + 1, &end, 10);
    }
  else
    {
      self->error_code = HTTP_MSG_CLIENT_SYNTAX;
      g_string_sprintf(self->error_info, "Invalid CONNECT request.");
      /*LOG
        This message indicates that the received CONNECT request did not
        include a port number to connect to.
      */
      z_proxy_log(self, HTTP_VIOLATION, 1, "Missing port number in CONNECT request; url='%s'", self->request_url->str);
      z_proxy_return(self, FALSE);
    }

  HttpURL url_parts;
  http_init_url(&url_parts);
  g_string_assign_len(url_parts.host, remote_host, remote_host_len);
  url_parts.port = remote_port;
  if (!HttpUrlFilter::get_instance().filter_url(self, self->request_url->str, url_parts))
    {
      http_destroy_url(&url_parts);
      return false;
    }
  http_destroy_url(&url_parts);

  if (http_parent_proxy_enabled(self))
    {
      g_string_assign(self->remote_server, self->parent_proxy->str);
      self->remote_port = self->parent_proxy_port;
    }
  else
    {
      /* From buffer is longer than we want to copy. */
      g_string_assign_len(self->remote_server, remote_host, remote_host_len);
      self->remote_port = remote_port;
    }

  if (!http_connect_server(self))
    z_proxy_return(self, FALSE);

  if (http_parent_proxy_enabled(self))
    {
      GString *request = g_string_sized_new(64);

      http_format_request(self, FALSE, request);

      if (http_write(self, EP_SERVER, request->str, request->len) != G_IO_STATUS_NORMAL)
        {
          g_string_free(request, TRUE);
          z_proxy_return(self, FALSE);
        }

      g_string_free(request, TRUE);

      if (!http_fetch_response(self))
        z_proxy_return(self, FALSE);

      if (self->response_code != 200)
        {
          /*LOG
            This message indicates that the our parent proxy
            refused our CONNECT request. It is likely that the
            parent proxy does not permit CONNECT method.
          */
          z_proxy_log(self, HTTP_ERROR, 1, "Parent proxy refused our CONNECT request; host='%.*s', port='%d'", remote_host_len, remote_host, remote_port);
          z_proxy_log(self, HTTP_DEBUG, 6, "Processing response and headers (CONNECT);");

          if (!http_process_response(self) ||
              !http_filter_response(self) ||
              !http_copy_response(self))
            {
              z_proxy_log(self, HTTP_ERROR, 2, "Error copying CONNECT response, or CONNECT response rejected by policy; request='%s', response='%d'", self->request_method->str, self->response_code);
            }

          z_proxy_return(self, FALSE);
        }
    }

  /*LOG
    This message reports that CONNECT method is in use, and
    CONNECT method was accepted by out parent proxy.
  */
  z_proxy_log(self, HTTP_DEBUG, 6, "Starting connect method;");

  if (!http_parent_proxy_enabled(self))
    {
      success = const_cast<char*>("HTTP/1.0 200 Connection established\r\n\r\n");

      if (http_write(self, EP_CLIENT, success, strlen(success)) != G_IO_STATUS_NORMAL)
        z_proxy_return(self, FALSE); /* hmm... I/O error */
    }
  else
    {
      if (!http_process_response(self) ||
          !http_filter_response(self) ||
          !http_copy_response(self))
        {
          z_proxy_log(self, HTTP_ERROR, 2, "Error copying CONNECT response, or CONNECT response rejected by policy; request='%s', response='%d'", self->request_method->str, self->response_code);
          z_proxy_return(self, FALSE);
        }
    }

  /* FIXME: flush already buffered data, before starting plug */

  /* NOTE: the child proxy uses the Python variables session.client_stream
   * and session.server_stream as its streams (see bug: #10347)
   */
  for (i = EP_CLIENT; i < EP_MAX; i++)
    {
      while (self->super.endpoints[i]->child)
        self->super.endpoints[i] = z_stream_pop(self->super.endpoints[i]);
    }

  z_policy_lock(self->super.thread);
  res = z_policy_call(self->super.handler, "connectMethod", z_policy_var_build("()"), &called, self->super.session_id);

  if (!res || res == z_policy_none)
    {
      /*LOG
        This message indicates that an internal error occurred, the
        connectMethod function did not return an integer. Please report this
        event to the BalaSys Development Team (at devel@balasys.hu).
      */
      z_proxy_log(self, HTTP_ERROR, 1, "Internal error, connectMethod is expected to return a proxy instance;");
      z_proxy_report_policy_abort(&(self->super));
      self->error_code = HTTP_MSG_POLICY_SYNTAX;
      z_policy_var_unref(res);
      z_policy_unlock(self->super.thread);
      z_proxy_leave(self);
      return FALSE;
    }

  z_policy_var_unref(res);
  z_policy_unlock(self->super.thread);

  /* release, but don't close fds */
  for (i = EP_CLIENT; i < EP_MAX; i++)
    {
      z_stream_unref(self->super.endpoints[i]);
      self->super.endpoints[i] = NULL;
    }

  z_proxy_return(self, TRUE);
}

static void
http_main(ZProxy *s)
{
  HttpProxy *self = Z_CAST(s, HttpProxy);
  gint rerequest_attempts;

  z_proxy_enter(self);
  self->request_count = 0;
  http_client_stream_init(self);

  /* loop for keep-alive */
  while (1)
    {
      self->error_code = HTTP_MSG_NOT_ASSIGNED;

      /*LOG
        This message reports that Zorp is fetching the request and the
        headers from the client.
      */
      z_proxy_log(self, HTTP_DEBUG, 6, "Fetching request and headers;");

      /* fetch request */
      if (!http_fetch_request(self))
        {
          if (self->error_code == HTTP_MSG_NOT_ASSIGNED)
            self->error_code = HTTP_MSG_CLIENT_SYNTAX;

          goto exit_request_loop;
        }

      if (!z_proxy_loop_iteration(s))
        break;

      /*LOG
        This message reports that Zorp is processing the fetched request and
        the headers.
      */
      z_proxy_log(self, HTTP_DEBUG, 6, "processing request and headers;");

      if (!http_process_request(self))
        {
          if (self->error_code == HTTP_MSG_NOT_ASSIGNED)
            self->error_code = HTTP_MSG_CLIENT_SYNTAX;

          goto exit_request_loop;
        }

      if (self->max_keepalive_requests != 0 &&
          self->request_count >= self->max_keepalive_requests - 1)
        {
          /*LOG
            This message reports that the maximum number of requests in a keep-alive loop is
            reached, and Zorp is closing after this request. Check the max_keepalive_request
            attribute.
          */
          z_proxy_log(self, HTTP_POLICY, 3,
                      "Maximum keep-alive request reached, setting connection mode to close; count='%d', max='%d'",
                      self->request_count, self->max_keepalive_requests);
          self->connection_mode = HTTP_CONNECTION_CLOSE;
        }

      /*LOG
        This message reports that Zorp is filtering the processed
        request and the headers.
      */
      z_proxy_log(self, HTTP_DEBUG, 6, "Filtering request and headers;");

      if (!http_filter_request(self))
        {
          if (self->error_code == HTTP_MSG_NOT_ASSIGNED)
            self->error_code = HTTP_MSG_POLICY_SYNTAX;

          goto exit_request_loop;
        }

      if (self->send_custom_response)
        goto exit_request_loop;

      /*LOG
        This message indicates that Zorp is recechecking the HTTP request
        after possible changes performed by the policy layer.
      */
      z_proxy_log(self, HTTP_DEBUG, 6, "Reprocessing filtered request;");

      if (!http_process_filtered_request(self))
        {
          if (self->error_code == HTTP_MSG_NOT_ASSIGNED)
            self->error_code = HTTP_MSG_CLIENT_SYNTAX;

          goto exit_request_loop;
        }

      if (self->server_protocol == HTTP_PROTO_HTTP || self->server_protocol == HTTP_PROTO_HTTPS)
        {
          gboolean retry;

          if ((self->request_flags & HTTP_REQ_FLG_CONNECT))
            {
              if (http_handle_connect(self))
                z_proxy_return(self); /* connect method was successful, we can now safely quit */

              goto exit_request_loop;
            }

          rerequest_attempts = self->rerequest_attempts;

          while (1)
            {
              retry = FALSE;
              /*LOG
                This message reports that Zorp is sending the filtered request and
                headers, and copies the requests data to the server.
              */
              z_proxy_log(self, HTTP_DEBUG, 6, "Sending request and headers, copying request data;");

              if (!retry && !http_copy_request(self))
                {
                  if (self->error_code == HTTP_MSG_NOT_ASSIGNED)
                    self->error_code = HTTP_MSG_CLIENT_SYNTAX;

                  retry = TRUE;
                }

              /*LOG
                This message reports that Zorp is fetching the response and headers
                from the server.
              */
              z_proxy_log(self, HTTP_DEBUG, 6, "Fetching response and headers;");

              if (!retry && !http_fetch_response(self))
                {
                  if (self->error_code == HTTP_MSG_NOT_ASSIGNED)
                    self->error_code = HTTP_MSG_SERVER_SYNTAX;

                  retry = TRUE;
                }

              if (retry && rerequest_attempts > 1)
                {
                  z_proxy_log(self, HTTP_ERROR, 3, "Server request failed, retrying; attempts='%d'", rerequest_attempts);
                  self->force_reconnect = TRUE;
                  self->error_code = HTTP_MSG_NOT_ASSIGNED;
                  rerequest_attempts--;
                  continue;
                }
              else if (retry)
                {
                  goto exit_request_loop;
                }
              else
                {
                  break;
                }
            }

          if (!z_proxy_loop_iteration(s))
            goto exit_request_loop;

          /*LOG
            This message reports that Zorp is processing the fetched response
            and the headers.
          */
          z_proxy_log(self, HTTP_DEBUG, 6, "Processing response and headers;");

          if (!http_process_response(self))
            {
              if (self->error_code == HTTP_MSG_NOT_ASSIGNED)
                self->error_code = HTTP_MSG_SERVER_SYNTAX;

              goto exit_request_loop;
            }

          /*LOG
            This message reports that Zorp is filtering the processed
            response and the headers.
          */
          z_proxy_log(self, HTTP_DEBUG, 6, "Filtering response and headers;");

          if (!http_filter_response(self))
            {
              if (self->error_code == HTTP_MSG_NOT_ASSIGNED)
                self->error_code = HTTP_MSG_POLICY_SYNTAX;

              goto exit_request_loop;
            }

          /*LOG
            This message reports that Zorp is sending the filtered
            response and headers, and copies the response data to the client.
          */
          z_proxy_log(self, HTTP_DEBUG, 6, "Copying response and headers, copying response data;");

          if (!http_copy_response(self))
            {
              if (self->error_code == HTTP_MSG_NOT_ASSIGNED)
                self->error_code = HTTP_MSG_SERVER_SYNTAX;

              goto exit_request_loop;
            }
        }
      else if (self->server_protocol == HTTP_PROTO_FTP)
        {
          if (!http_handle_ftp_request(self))
            {
              if (self->error_code == HTTP_MSG_NOT_ASSIGNED)
                self->error_code = HTTP_MSG_FTP_ERROR;
            }

          self->connection_mode = HTTP_CONNECTION_CLOSE;
        }
      else
        {
          /*LOG
            This message indicates an internal error in HTTP proxy. Please
            report this event to the BalaSys Development Team (at
	    devel@balasys.hu).
          */
          z_proxy_log(self, CORE_ERROR, 1, "Internal error, invalid server_protocol; server_protocol='%d'", self->server_protocol);
        }

      if (self->connection_mode == HTTP_CONNECTION_CLOSE)
        goto exit_request_loop;

      if (self->server_connection_mode == HTTP_CONNECTION_CLOSE)
        {
          /* close the server connection, but keep the client connection in-tact */
          self->force_reconnect = TRUE;
        }

      self->request_count++;

      /* NOTE:
       * In keepalive mode we have to disable authentication after the first round.
       */
      if (self->auth && !(self->auth_by_form || self->auth_by_cookie))
        {
          z_policy_lock(self->super.thread);

          z_policy_var_unref(self->auth);
          self->auth = NULL;

          z_policy_unlock(self->super.thread);
        }
    }

 exit_request_loop:
  /*LOG
    This message reports that Zorp is exiting the keep-alive loop and
    closing the connection.
  */
  z_proxy_log(self, HTTP_DEBUG, 6, "exiting keep-alive loop;");

  if (self->error_code > 0)
    {
      http_error_message(self, self->error_status, self->error_code, self->error_info);
    }
  else if (self->send_custom_response)
    {
      self->send_custom_response = FALSE;
      http_send_custom_response(self, self->error_status, self->error_msg, self->error_headers, self->custom_response_body);
    }

  /* in some cases the client might still have some data already queued to us,
   * fetch and ignore that data to avoid the RST sent in these cases
   */
  http_fetch_buffered_data(self);

  if (self->error_code <= 0 && self->reset_on_close)
    {
      int fd;

      fd = z_stream_get_fd(self->super.endpoints[EP_CLIENT]);

      if (fd >= 0)
        {
          struct linger l;

          l.l_onoff = 1;
          l.l_linger = 0;
          setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
        }

      /* avoid z_stream_shutdown in the destroy path */
      z_stream_close(self->super.endpoints[EP_CLIENT], NULL);
      z_stream_unref(self->super.endpoints[EP_CLIENT]);
      self->super.endpoints[EP_CLIENT] = NULL;
    }

  z_proxy_return(self);
}

static gboolean
http_config(ZProxy *s)
{
  HttpProxy *self = Z_CAST(s, HttpProxy);

  http_config_set_defaults(self);

  http_register_vars(self);

  if (Z_SUPER(s, ZProxy)->config(s))
    {
      http_config_init(self);

      z_proxy_ssl_set_force_connect_at_handshake(s, TRUE);

      return TRUE;
    }

  return FALSE;
}

static void
http_proxy_free(ZObject *s)
{
  HttpProxy *self = Z_CAST(s, HttpProxy);
  guint i;

  z_enter();

  for (i = EP_CLIENT; i < EP_MAX; i++)
    http_destroy_headers(&self->headers[i]);

  if (self->request_data)
    z_blob_unref(self->request_data);

  g_string_free(self->old_auth_header, TRUE);
  g_string_free(self->auth_header_value, TRUE);
  g_string_free(self->response_msg, TRUE);
  g_string_free(self->connected_server, TRUE);
  g_string_free(self->remote_server, TRUE);
  g_string_free(self->request_url, TRUE);
  http_destroy_url(&self->request_url_parts);
  /* NOTE: hashes are freed up by pyvars */
  z_poll_unref(self->poll);
  z_proxy_free_method(s);
  z_return();
}

static ZProxy *
http_proxy_new(ZProxyParams *params)
{
  HttpProxy *self;

  z_enter();
  self = Z_CAST(z_proxy_new(Z_CLASS(HttpProxy), params), HttpProxy);
  z_return((&self->super));
}

static void http_proxy_free(ZObject *s);

ZProxyFuncs http_proxy_funcs =
  {
    {
      Z_FUNCS_COUNT(ZProxy),
      http_proxy_free,
    },           /* super */
    http_config, /*config */
    NULL,        /* startup */
    http_main,   /* main */
    NULL,        /* shutdown */
    NULL,        /* destroy */
    NULL,        /* nonblocking_init */
    NULL,        /* nonblocking_deinit */
    NULL,        /* wakeup */
  };

Z_CLASS_DEF(HttpProxy, ZProxy, http_proxy_funcs);

static ZProxyModuleFuncs http_module_funcs =
  {
    /* .create_proxy = */ http_proxy_new,
    /* .module_py_init = */ NULL,
  };

gint
zorp_module_init(void)
{
  http_proto_init();

  HttpUrlFilter::get_instance().init_backend();

  auth_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, http_auth_destroy);
  z_registry_add("http", ZR_PROXY, &http_module_funcs);
  return TRUE;
}
