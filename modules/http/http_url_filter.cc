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
 *
 ***************************************************************************/

#include "http_url_filter.h"

#include <array>

#include <netdb.h>
#include <sys/socket.h>

#include <zorp/urlfilter_blacklist.h>

static bool has_url_filter_license = false;
static bool url_filter_license_error_logged = false;
static std::unique_ptr<UrlFilter> url_filter = nullptr;

struct MergedUrlCategories
{
  static constexpr int MAX_TAGS = 3;
  std::array<std::string, UrlFilter::MAX_CATEGORIES * MAX_TAGS> category = {};
  std::array<HttpUrlCategoryTag, UrlFilter::MAX_CATEGORIES * MAX_TAGS> category_tag = {};
  unsigned num_categories = 0;
};

char *http_get_host_or_ip(char *str, int len, char *buf, gboolean host)
{
  struct addrinfo *result, *rp, hints;
  int s;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_INET;
  s = getaddrinfo(str, 0, &hints, &result);

  if (s != 0)
    {
      return str;
    }

  for (rp = result; rp != NULL; rp = rp->ai_next)
    {
      if (host)
        {
          s = getnameinfo(rp->ai_addr, rp->ai_addrlen, buf, len, 0, 0, 0);
        }
      else
        {
          const gint IP_BUF_SIZE = 32;
          gchar ipbuf[IP_BUF_SIZE];
          g_snprintf(buf, len, "%s",
                     z_inet_ntoa(ipbuf, IP_BUF_SIZE, ((struct sockaddr_in*) rp->ai_addr)->sin_addr));
        }
    }

  freeaddrinfo(result);
  return buf;
}

char* http_get_ip(char *s, char *outbuf, int len)
{
  return http_get_host_or_ip(s, len, outbuf, FALSE);
}

char* http_get_host(char *s, char *outbuf, int len)
{
  return http_get_host_or_ip(s, len, outbuf, TRUE);
}

static const gchar *http_category_tag_name(const enum HttpUrlCategoryTag tag)
{
  static const gchar *category_tag_to_string[] =
    {
      "URL",
      "IP address of server",
      "reverse lookup for the IP address of server"
    };

  g_assert(tag < CATEGORY_NUM);
  return category_tag_to_string[tag];
}

static void
http_tag_zblresult(UrlFilter::Result &result, enum HttpUrlCategoryTag tag)
{
  for (auto &category_tag : result.category_tag)
    category_tag = tag;
}

static void
http_join_urlfilter_results(MergedUrlCategories &merged_categories, const UrlFilter::Result &result)
{
  assert(merged_categories.num_categories + result.num_categories <= merged_categories.category.size());

  std::copy(result.category.begin(), result.category.begin() + result.num_categories,
            merged_categories.category.begin() + merged_categories.num_categories);

  std::copy(result.category_tag.begin(), result.category_tag.begin() + result.num_categories,
            merged_categories.category_tag.begin() + merged_categories.num_categories);

  merged_categories.num_categories += result.num_categories;
}

char *
http_from_url(char *buf, gint size, char *host, const char *file, char* query)
{
  if (file)
    {
      while (file[0] == '/')
        file++;
    }
  else file = "";

  if (query && query[0] != 0)
    {
      g_snprintf(buf, size, "%s/%s?%s", host, file, query);
    }
  else
    {
      g_snprintf(buf, size, "%s/%s", host, file);
    }

  return buf;
}

enum class UrlLookupMode
{
  Extended,
  Simple
};

static MergedUrlCategories
http_url_filter_lookup_categories(HttpProxy *self,
                                  UrlFilter *url_filter,
                                  const HttpURL &url_parts,
                                  const UrlLookupMode lookup_mode)
{
  MergedUrlCategories merged_categories;
  std::array<char, 4096> url_buf, ip_buf, host_buf, tmp_buf;

  http_from_url(url_buf.data(), url_buf.size(),
                url_parts.host->str,
                url_parts.file->str,
                url_parts.query->str);

  if (lookup_mode == UrlLookupMode::Extended)
    {
      http_from_url(ip_buf.data(), ip_buf.size(),
                    http_get_ip(url_parts.host->str, tmp_buf.data(), tmp_buf.size()),
                    url_parts.file->str,
                    url_parts.query->str);

      http_from_url(host_buf.data(), host_buf.size(),
                    http_get_host(url_parts.host->str, tmp_buf.data(), tmp_buf.size()),
                    url_parts.file->str,
                    url_parts.query->str);

      z_proxy_log(self, HTTP_DEBUG, 6,
                  "URL filter lookup; url='%s', ip='%s', host='%s'",
                  url_buf.data(), ip_buf.data(), host_buf.data());

      UrlFilter::Result host = url_filter->lookup_url(host_buf.data());
      http_tag_zblresult(host, CATEGORY_FOR_REVERSE_HOSTNAME);
      http_join_urlfilter_results(merged_categories, host);

      UrlFilter::Result ip = url_filter->lookup_url(ip_buf.data());
      http_tag_zblresult(ip, CATEGORY_FOR_IP);
      http_join_urlfilter_results(merged_categories, ip);
    }
  else
    {
      z_proxy_log(self, HTTP_DEBUG, 6,
                  "URL filter lookup; url='%s'", url_buf.data());
    }

  UrlFilter::Result url = url_filter->lookup_url(url_buf.data());
  http_tag_zblresult(url, CATEGORY_FOR_URL);
  http_join_urlfilter_results(merged_categories, url);

  return merged_categories;
}

static void
build_and_log_category_list(HttpProxy *self, std::string_view url, const MergedUrlCategories &result)
{
  z_proxy_enter(self);

  if (self->request_categories)
    z_policy_var_unref(self->request_categories);

  self->request_categories = z_policy_tuple_new(result.num_categories);

  GString *category_list = g_string_new("");

  for (unsigned i = 0; i < result.num_categories; ++i)
    {
      z_policy_tuple_setitem(self->request_categories, i, PyString_FromString(result.category[i].c_str()));

      if (i)
        g_string_append(category_list, ", ");

      g_string_append(category_list, result.category[i].c_str());
    }

  if (result.num_categories != 0)
    {
      /*LOG
        This message indicates that the requested URL matched at
        least one category.*/
      z_proxy_log(self, HTTP_ACCOUNTING, 4,
                  "Found category match(es) for URL; url='%s', category='%s'",
                  url.data(), category_list->str);
    }

  g_string_free(category_list, TRUE);

  z_proxy_leave(self);
}

static gint
evaluate_url_category_policy(HttpProxy *self, ZPolicyObj *policy_value, guint *error_status, const gchar **error_info)
{
  guint res;

  z_proxy_enter(self);

  if (z_policy_tuple_get_verdict(policy_value, &res))
    {
      ZPolicyObj *action = NULL;
      gint tmp;

      switch (res)
        {
        case HTTP_URL_REJECT:

          if (z_policy_var_parse_tuple(policy_value, "i|O", &tmp, &action) && action &&
              z_policy_tuple_check(action) &&
              z_policy_var_parse_tuple(action, "is", error_status, error_info))
            {
            }
          else
            {
              *error_status = 403;
              *error_info = "Access to this site is prohibited by the company policy.";
            }

          break;

        case HTTP_URL_REDIRECT:

          if (z_policy_var_parse_tuple(policy_value, "is", &tmp, error_info))
            {
              *error_status = 301;
            }
          else
            {
              /* there is no default value for redirect, return error */
              z_proxy_return(self, -1);
            }

          break;
        }
    }

  z_proxy_return(self, res);
}

static std::string_view
get_verdict_string(const int verdict)
{
  if (verdict == HttpUrlVerdict::HTTP_URL_ACCEPT)
    return "ACCEPT";
  else if (verdict == HttpUrlVerdict::HTTP_URL_REJECT)
    return "REJECT";
  else if (verdict == HttpUrlVerdict::HTTP_URL_REDIRECT)
    return "REDIRECT";

  return std::string_view{};
}

static HttpUrlVerdict
evaluate_category_list(HttpProxy *self, const MergedUrlCategories &result,
                       gint *offending_category_index,
                       guint *error_status, const gchar **error_info)
{
  HttpUrlVerdict res = HTTP_URL_REJECT;

  z_proxy_enter(self);

  *offending_category_index = -1;
  *error_status = 403;
  *error_info = "Invalid URL filtering policy settings";

  gboolean match_found = FALSE;

  for (unsigned i = 0; i < result.num_categories; ++i)
    {
      gint current_verdict;

      ZPolicyObj *f = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->url_category, result.category[i].c_str()));

      if (f)
        {
          guint eval_error_status;
          const gchar *eval_error_info;
          current_verdict = evaluate_url_category_policy(self, f, &eval_error_status, &eval_error_info);

          if (current_verdict >= 0)
            {
              z_proxy_log(self, HTTP_DEBUG, 5,
                          "Found category action policy; category='%s', verdict='%s'",
                          result.category[i].c_str(), get_verdict_string(current_verdict).data());

              /*
               * if the url was already categorized as HTTP_URL_REJECT
               * then it won't be overridden by any verdict.
               * HTTP_URL_ACCEPT can be overridden by HTTP_URL_REDIRECT
               */
              if ((match_found && res == HTTP_URL_REJECT) ||
                  (res == HTTP_URL_REDIRECT && current_verdict == HTTP_URL_ACCEPT))
                continue;

              switch (current_verdict)
                {
                case HTTP_URL_REJECT:
                  *offending_category_index = i;
                  break;

                case HTTP_URL_ACCEPT:
                  break;

                case HTTP_URL_REDIRECT:
                  *offending_category_index = i;
                  break;
                }

              *error_status = eval_error_status;
              *error_info = eval_error_info;
              res = static_cast<HttpUrlVerdict>(current_verdict);
            }
          else
            z_proxy_log(self, HTTP_DEBUG, 5,
                        "Failed to parse action policy tuple for category; category='%s', verdict='%s'",
                        result.category[i].c_str(), get_verdict_string(current_verdict).data());

          match_found = true;
        }
    }

  if (!match_found)
    {
      /* Try the '*' universal match */
      ZPolicyObj *f = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->url_category, "*"));

      if (f)
        {
          match_found = TRUE;
          gint verdict = evaluate_url_category_policy(self, f, error_status, error_info);

          if (verdict >= 0)
            {
              z_proxy_log(self, HTTP_DEBUG, 5, "Matched by catch-all action policy; verdict='%s'",
                          get_verdict_string(verdict).data());
              res = static_cast<HttpUrlVerdict>(verdict);
            }
          else
            {
              z_proxy_log(self, HTTP_DEBUG, 5, "Failed to parse tuple for catch-all action policy;");
            }
        }
    }

  if (!match_found)
    {
      /* No match was found in the policy hash, this means that even though the
       * request matched a category, the policy hash did not have a verdict for
       * that category. In this case we accept the request.
       */
      z_proxy_log(self, HTTP_DEBUG, 5, "Accepting request because no action policy has been configured for matching categories;");
      res = HTTP_URL_ACCEPT;
    }

  z_proxy_return(self, res);
}

void
http_url_filter_set_license_state(bool has_license)
{
  has_url_filter_license = has_license;
}

void
http_url_filter_init()
{
  if (has_url_filter_license && !url_filter)
    {
      url_filter = std::make_unique<UrlFilterBlacklist>();
      if (url_filter && !url_filter->is_initialized())
        url_filter.reset();
    }
}

gboolean
http_url_filter(HttpProxy *self, std::string_view url_str, const HttpURL &url_parts)
{
  const gchar *error_info = NULL;
  guint error_status;
  gint offending_category_index = -1;

  z_proxy_enter(self);

  if (!self->enable_url_filter)
    {
      z_proxy_return (self, TRUE);
    }

  if (!has_url_filter_license)
    {
      if (!url_filter_license_error_logged)
        {
          z_log(0, CORE_ERROR, 3, "Missing url-filter option in license;");
          url_filter_license_error_logged = TRUE;
        }

      z_proxy_return(self, TRUE);
    }

  if (!url_filter)
    {
      z_proxy_log(self, HTTP_ERROR, 1, "URL filter is uninitialized;");
      self->error_code = HTTP_MSG_INTERNAL;
      self->error_status = 500;
      return false;
    }

  UrlLookupMode lookup_mode = UrlLookupMode::Simple;

  if (self->enable_url_filter_dns)
    {
      z_proxy_log(self, HTTP_DEBUG, 5, "URL filter dns lookup enabled;");
      lookup_mode = UrlLookupMode::Extended;
    }

  const MergedUrlCategories categories =
    http_url_filter_lookup_categories(self, url_filter.get(), url_parts, lookup_mode);

  gboolean res = FALSE;
  HttpUrlVerdict resolution;

  z_policy_lock(self->super.thread);

  if (categories.num_categories == 0)
    {
      /* no categories found, return verdict for uncategorized action */
      resolution = static_cast<HttpUrlVerdict>(evaluate_url_category_policy(self, self->url_filter_uncategorized_action, &error_status, &error_info));
    }
  else
    {
      build_and_log_category_list(self, url_str, categories);
      resolution = evaluate_category_list(self, categories, &offending_category_index, &error_status, &error_info);
    }

  z_policy_unlock(self->super.thread);

  z_proxy_log(self, HTTP_DEBUG, 5,
              "Final decision was made; verdict='%s'",
              get_verdict_string(resolution).data());

  switch (resolution)
    {
    case HTTP_URL_ACCEPT:
      res = TRUE;
      break;

    case HTTP_URL_REJECT:

      /*LOG
        This message indicates that the requested HTTP request was rejected by Zorp
        because the requested URL matched a category that was configured to be rejected
        in the policy. */
      if (offending_category_index < 0)
        z_proxy_log(self, HTTP_POLICY, 3, "Rejected by URL filter because no action policy was found for this URL; url='%s'",
                    url_str.data());
      else
        z_proxy_log(self, HTTP_POLICY, 3, "Rejected by URL filter; category='%s', category_source='%s', url='%s'",
                    categories.category[offending_category_index].c_str(),
                    http_category_tag_name(categories.category_tag[offending_category_index]),
                    url_str.data());

      self->error_code = HTTP_MSG_POLICY_VIOLATION;
      self->error_status = error_status;
      g_string_printf(self->error_info, "%s", error_info);
      res = FALSE;
      break;

    case HTTP_URL_REDIRECT:

      /*LOG
        This message indicates that the requested HTTP request has been redirected by Zorp
        because the requested URL matched a category that we configured to be redirected. */
      if (offending_category_index < 0)
        z_proxy_log(self, HTTP_POLICY, 3, "Redirected by URL filter because no action policy was found for this URL; url='%s'",
                    url_str.data());
      else
        z_proxy_log(self, HTTP_POLICY, 3, "Redirected by URL filter; category='%s', category_source='%s', url='%s', target='%s'",
                    categories.category[offending_category_index].c_str(),
                    http_category_tag_name(categories.category_tag[offending_category_index]),
                    url_str.data(),
                    error_info);

      self->error_code = HTTP_MSG_REDIRECT;
      self->error_status = error_status;
      g_string_printf(self->error_info, "%s", error_info);
      g_string_sprintfa(self->error_headers, "Location: %s\r\n", error_info);
      res = FALSE;
      break;
    }

  z_proxy_return (self, res);
}
