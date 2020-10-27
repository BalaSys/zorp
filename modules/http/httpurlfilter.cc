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

#include "httpurlfilter.h"

#include <array>
#include <optional>

#include <netdb.h>
#include <sys/socket.h>

HttpUrlFilter &
HttpUrlFilter::get_instance()
{
  static HttpUrlFilter instance;
  return instance;
}

bool
HttpUrlFilter::get_license_state() const
{
  return has_license;
}

void
HttpUrlFilter::set_license_state(const bool has_license)
{
  this->has_license = has_license;
}

void
HttpUrlFilter::init_backend()
{
  if (!has_license)
    return;

  if (backend)
    return;

  backend = std::make_unique<UrlFilterBlacklist>();

  if (backend && !backend->is_initialized())
    backend.reset();
}

bool
HttpUrlFilter::is_backend_initialized()
{
  return static_cast<bool>(backend);
}

bool
HttpUrlFilter::filter_url(HttpProxy *proxy, std::string_view url_str, const HttpURL &url_parts)
{
  if (!proxy->enable_url_filter)
    return true;

  if (!get_license_state())
    {
      if (!get_license_error_logged())
        {
          z_log(nullptr, CORE_ERROR, 3, "Missing url-filter option in license;");
          set_license_error_logged(true);
        }

      return true;
    }

  if (!is_backend_initialized())
    {
      z_proxy_log(proxy, HTTP_ERROR, 1, "URL filtering cannot be done as the initialization has failed at startup;");
      proxy->error_code = HTTP_MSG_INTERNAL;
      proxy->error_status = 500;
      return false;
    }

  UrlLookupMode lookup_mode = UrlLookupMode::Simple;

  if (proxy->enable_url_filter_dns)
    {
      z_proxy_log(proxy, HTTP_DEBUG, 5, "URL filter dns lookup enabled;");
      lookup_mode = UrlLookupMode::Extended;
    }

  const MergedUrlCategories categories =
    lookup_categories(proxy, backend.get(), url_parts, lookup_mode);

  HttpUrlVerdict verdict = HttpUrlVerdict::REJECT;
  int offending_category_index = -1;
  unsigned error_status = 0;
  std::string_view error_info;

  z_policy_lock(proxy->super.thread);

  if (categories.num_categories)
    {
      export_category_list(proxy->request_categories, categories);

      if (const std::string &line = get_category_list_string(categories); !line.empty())
        {
          z_proxy_log(proxy, HTTP_ACCOUNTING, 4,
                      "Found category match(es) for URL; url='%s', category='%s'",
                      url_str.data(), line.c_str());
        }
      else
        {
          z_proxy_log(proxy, HTTP_ACCOUNTING, 4, "Category match(es) have not found for URL; url='%s'", url_str.data());
        }

      verdict = evaluate_category_action_policies(proxy, categories,
                                                  offending_category_index,
                                                  error_status, error_info);
    }
  else
    {
      verdict = evaluate_uncategorized_category_action_policy(proxy,
                                                              error_status, error_info);
    }

  z_policy_unlock(proxy->super.thread);

  z_proxy_log(proxy, HTTP_DEBUG, 5,
              "Final decision was made; verdict='%s'",
              get_verdict_string(verdict).data());

  bool resolution = false;

  switch (verdict)
    {
    case HttpUrlVerdict::ACCEPT:
      resolution = true;
      break;

    case HttpUrlVerdict::REJECT:

      /*LOG
        This message indicates that the requested HTTP request was rejected by Zorp
        because the requested URL matched a category that was configured to be rejected
        in the policy. */
      if (offending_category_index < 0)
        {
          z_proxy_log(proxy, HTTP_POLICY, 3,
                      "Rejected by URL filter because no action policy was found for this URL; url='%s'",
                      url_str.data());
        }
      else
        {
          z_proxy_log(proxy, HTTP_POLICY, 3,
                      "Rejected by URL filter; category='%s', category_source='%s', url='%s'",
                      categories.category[offending_category_index].c_str(),
                      z_map_get_value(httpurlcategorytag_strings, categories.category_tag[offending_category_index]).data(),
                      url_str.data());
        }

      proxy->error_code = HTTP_MSG_POLICY_VIOLATION;
      proxy->error_status = error_status;
      g_string_printf(proxy->error_info, "%s", error_info.data());
      resolution = false;
      break;

    case HttpUrlVerdict::REDIRECT:

      /*LOG
        This message indicates that the requested HTTP request has been redirected by Zorp
        because the requested URL matched a category that we configured to be redirected. */
      if (offending_category_index < 0)
        {
          z_proxy_log(proxy, HTTP_POLICY, 3,
                      "Redirected by URL filter because no action policy was found for this URL; url='%s'",
                      url_str.data());

        }
      else
        {
          z_proxy_log(proxy, HTTP_POLICY, 3,
                      "Redirected by URL filter; category='%s', category_source='%s', url='%s', target='%s'",
                      categories.category[offending_category_index].c_str(),
                      z_map_get_value(httpurlcategorytag_strings, categories.category_tag[offending_category_index]).data(),
                      url_str.data(), error_info.data());
        }

      proxy->error_code = HTTP_MSG_REDIRECT;
      proxy->error_status = error_status;
      g_string_printf(proxy->error_info, "%s", error_info.data());
      g_string_sprintfa(proxy->error_headers, "Location: %s\r\n", error_info.data());
      resolution = false;
      break;
    }

  return resolution;
}

bool
HttpUrlFilter::get_license_error_logged() const
{
  return is_license_error_logged;
}

void
HttpUrlFilter::set_license_error_logged(const bool is_license_error_logged)
{
  this->is_license_error_logged = is_license_error_logged;
}

std::optional<HttpUrlVerdict>
HttpUrlFilter::evaluate_category_action_policy(HttpProxy *proxy, ZPolicyObj *policy_value,
                                               unsigned &error_status,
                                               std::string_view &error_info)
{
  constexpr std::string_view error_msg = "Failed to parse tuple for action policy;";
  unsigned result = 0;
  if (!z_policy_tuple_get_verdict(policy_value, &result))
    {
      z_proxy_log(proxy, HTTP_ERROR, 1, "%s", error_msg.data());
      return std::nullopt;
    }

  if (result < static_cast<int>(HttpUrlVerdict::FIRST) ||
      result > static_cast<int>(HttpUrlVerdict::LAST))
    {
      z_proxy_log(proxy, HTTP_ERROR, 1, "%s", error_msg.data());
      return std::nullopt;
    }

  ZPolicyObj *action = nullptr;
  int tmp = 0;
  const char *error_info_local = nullptr;

  switch (static_cast<HttpUrlVerdict>(result))
    {
      case HttpUrlVerdict::REJECT:
        if (!(z_policy_var_parse_tuple(policy_value, "i|O", &tmp, &action) &&
              action &&
              z_policy_tuple_check(action) &&
              z_policy_var_parse_tuple(action, "is", &error_status, &error_info_local)))
          {
            error_status = 403;
            error_info = "Access to this site is prohibited by the company policy.";
          }

        error_info = error_info_local;

        return {HttpUrlVerdict::REJECT};

      case HttpUrlVerdict::REDIRECT:
        if (!z_policy_var_parse_tuple(policy_value, "is", &tmp, &error_info_local))
          {
            // There is no default value for redirect, return with an error
            z_proxy_log(proxy, HTTP_ERROR, 1, "%s", error_msg.data());
            return std::nullopt;
          }

        error_status = 301;
        error_info = error_info_local;

        return {HttpUrlVerdict::REDIRECT};

      case HttpUrlVerdict::ACCEPT:
        /// @note Accept do not have any special parameter.
        return {HttpUrlVerdict::ACCEPT};
    }

  z_proxy_log(proxy, HTTP_ERROR, 1, "%s", error_msg.data());
  return std::nullopt;
}

HttpUrlVerdict
HttpUrlFilter::evaluate_category_action_policies(HttpProxy *proxy,
                                                 const MergedUrlCategories &result,
                                                 int &offending_category_index,
                                                 unsigned &error_status,
                                                 std::string_view &error_info)
{
  HttpUrlVerdict verdict = HttpUrlVerdict::REJECT;

  constexpr unsigned policy_error_status = 403;
  constexpr std::string_view policy_error_string = "Invalid URL filtering policy settings";

  bool action_policy_found = false;

  for (unsigned i = 0; i < result.num_categories; ++i)
    {
      ZPolicyObj *policy_value =
        static_cast<ZPolicyObj *>(g_hash_table_lookup(proxy->url_category, result.category[i].c_str()));

      if (!policy_value)
        continue;

      unsigned current_error_status = 0;
      std::string_view current_error_info;
      const auto current_verdict =
        evaluate_category_action_policy(proxy, policy_value, current_error_status, current_error_info);

      if (!current_verdict)
        {
          error_status = policy_error_status;
          error_info = policy_error_string;
          continue;
        }

      z_proxy_log(proxy, HTTP_DEBUG, 5,
                  "Found category action policy; category='%s', verdict='%s'",
                  result.category[i].c_str(), get_verdict_string(*current_verdict).data());

      // If the URL was already categorized as REJECT
      // then it won't be overridden by any verdict.
      // ACCEPT can be overridden only by REDIRECT
      if ((action_policy_found && verdict == HttpUrlVerdict::REJECT) ||
          (verdict == HttpUrlVerdict::REDIRECT && *current_verdict == HttpUrlVerdict::ACCEPT))
        continue;

      switch (*current_verdict)
        {
          case HttpUrlVerdict::REJECT:
            [[fallthrough]];
          case HttpUrlVerdict::REDIRECT:
            offending_category_index = i;
            error_status = current_error_status;
            error_info = current_error_info;
            break;
          case HttpUrlVerdict::ACCEPT:
            break;
        }

      verdict = *current_verdict;

      action_policy_found = true;
    }

  // Try the '*' universal match
  ZPolicyObj *policy_value = nullptr;
  if (!action_policy_found &&
      (policy_value = static_cast<ZPolicyObj *>(g_hash_table_lookup(proxy->url_category, "*"))))
    {
      if (const auto current_verdict = evaluate_category_action_policy(proxy, policy_value, error_status, error_info);
          current_verdict)
        {
          z_proxy_log(proxy, HTTP_DEBUG, 5,
                      "Matched by catch-all action policy; verdict='%s'",
                      get_verdict_string(*current_verdict).data());
          verdict = *current_verdict;
        }
      else
        {
          error_status = policy_error_status;
          error_info = policy_error_string;
        }

      action_policy_found = true;
    }

  if (!action_policy_found)
    {
      // No match was found in the policy hash, this means that even though the
      // request matched a category, the policy hash did not have a verdict for
      // that category. In this case we accept the request.
      z_proxy_log(proxy, HTTP_DEBUG, 5,
                  "Accepting request because no action policy has been configured for matching categories;");
      verdict = HttpUrlVerdict::ACCEPT;
    }

  return verdict;
}

HttpUrlVerdict
HttpUrlFilter::evaluate_uncategorized_category_action_policy(HttpProxy *proxy,
                                                             unsigned &error_status,
                                                             std::string_view &error_info)
{
  HttpUrlVerdict verdict = HttpUrlVerdict::REJECT;

  const auto current_verdict = evaluate_category_action_policy(proxy, proxy->url_filter_uncategorized_action,
                                                               error_status, error_info);
  if (current_verdict)
    verdict = *current_verdict;

  return verdict;
}

std::string_view
HttpUrlFilter::get_verdict_string(const HttpUrlVerdict verdict)
{
  switch (verdict)
    {
      case HttpUrlVerdict::REJECT:
        return "REJECT";
      case HttpUrlVerdict::REDIRECT:
        return "REDIRECT";
      case HttpUrlVerdict::ACCEPT:
        return "ACCEPT";
    }

  return std::string_view{};
}

char *
HttpUrlFilter::get_host_or_ip(char *str, int len, char *buf, gboolean host)
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

char *
HttpUrlFilter::get_ip(char *s, char *outbuf, int len)
{
  return get_host_or_ip(s, len, outbuf, FALSE);
}

char *
HttpUrlFilter::get_host(char *s, char *outbuf, int len)
{
  return get_host_or_ip(s, len, outbuf, TRUE);
}

void
HttpUrlFilter::tag_result(UrlFilter::Result &result, const HttpUrlCategoryTag tag)
{
  for (auto &category_tag : result.category_tag)
    category_tag = tag;
}

char *
HttpUrlFilter::http_from_url(char *buf, gint size, char *host, const char *file, char* query)
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

void
HttpUrlFilter::join_urlfilter_results(MergedUrlCategories &merged_categories,
                                      const UrlFilter::Result &result)
{
  assert(merged_categories.num_categories + result.num_categories <= merged_categories.category.size());

  std::copy(result.category.begin(), result.category.begin() + result.num_categories,
            merged_categories.category.begin() + merged_categories.num_categories);

  std::copy(result.category_tag.begin(), result.category_tag.begin() + result.num_categories,
            merged_categories.category_tag.begin() + merged_categories.num_categories);

  merged_categories.num_categories += result.num_categories;
}

MergedUrlCategories
HttpUrlFilter::lookup_categories(HttpProxy *proxy,
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
                    get_ip(url_parts.host->str, tmp_buf.data(), tmp_buf.size()),
                    url_parts.file->str,
                    url_parts.query->str);

      http_from_url(host_buf.data(), host_buf.size(),
                    get_host(url_parts.host->str, tmp_buf.data(), tmp_buf.size()),
                    url_parts.file->str,
                    url_parts.query->str);

      z_proxy_log(proxy, HTTP_DEBUG, 6,
                  "URL filter lookup; url='%s', ip='%s', host='%s'",
                  url_buf.data(), ip_buf.data(), host_buf.data());

      UrlFilter::Result host = url_filter->lookup_url(host_buf.data());
      tag_result(host, HttpUrlCategoryTag::REVERSE_HOSTNAME);
      join_urlfilter_results(merged_categories, host);

      UrlFilter::Result ip = url_filter->lookup_url(ip_buf.data());
      tag_result(ip, HttpUrlCategoryTag::IP);
      join_urlfilter_results(merged_categories, ip);
    }
  else
    {
      z_proxy_log(proxy, HTTP_DEBUG, 6,
                  "URL filter lookup; url='%s'", url_buf.data());
    }

  UrlFilter::Result url = url_filter->lookup_url(url_buf.data());
  tag_result(url, HttpUrlCategoryTag::URL);
  join_urlfilter_results(merged_categories, url);

  return merged_categories;
}

std::string
HttpUrlFilter::get_category_list_string(const MergedUrlCategories &categories)
{
  std::string output;
  for (unsigned i = 0; i < categories.num_categories; ++i)
    {
      if (i)
        output += "; ";

      output += categories.category[i].c_str();
    }

  return output;
}

void
HttpUrlFilter::export_category_list(ZPolicyObj *request_categories,
                                    const MergedUrlCategories &categories)
{
  if (request_categories)
    z_policy_var_unref(request_categories);

  request_categories = z_policy_tuple_new(categories.num_categories);

  for (unsigned i = 0; i < categories.num_categories; ++i)
    {
      z_policy_tuple_setitem(request_categories,
                             i,
                             PyString_FromString(categories.category[i].c_str()));
    }
}
