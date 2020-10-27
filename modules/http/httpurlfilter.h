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

#ifndef ZORP_MODULES_HTTPURLFILTER_H_INCLUDED
#define ZORP_MODULES_HTTPURLFILTER_H_INCLUDED

#include "http.h"

#include <atomic>
#include <string_view>

#include <zorp/urlfilter_blacklist.h>

struct MergedUrlCategories
{
  static constexpr int MAX_TAGS = 3;
  std::array<std::string, UrlFilter::MAX_CATEGORIES * MAX_TAGS> category = {};
  std::array<HttpUrlCategoryTag, UrlFilter::MAX_CATEGORIES * MAX_TAGS> category_tag = {};
  unsigned num_categories = 0;
};

class HttpUrlFilter final
{
public:
  ~HttpUrlFilter() = default;

  HttpUrlFilter(const HttpUrlFilter &) = delete;
  void operator=(const HttpUrlFilter &) = delete;

  static HttpUrlFilter &get_instance();

  /**
   * @warning Multi-thread unsafe.
   */
  bool get_license_state() const;

  /**
   * @warning Multi-thread unsafe.
   */
  void set_license_state(const bool has_license);

  /**
   * @warning Multi-thread unsafe.
   */
  void init_backend();

  /**
   * @warning Multi-thread unsafe.
   */
  bool is_backend_initialized();

  bool filter_url(HttpProxy *proxy, std::string_view url_str, const HttpURL &url_parts);

private:
  enum class UrlLookupMode
  {
    Extended,
    Simple
  };

  HttpUrlFilter() = default;

  bool get_license_error_logged() const;
  void set_license_error_logged(const bool is_license_error_logged);

  static std::optional<HttpUrlVerdict> evaluate_category_action_policy(HttpProxy *proxy, ZPolicyObj *policy_value,
                                                                       unsigned &error_status,
                                                                       std::string_view &error_info);

  static HttpUrlVerdict evaluate_category_action_policies(HttpProxy *proxy,
                                                          const MergedUrlCategories &result,
                                                          int &offending_category_index,
                                                          unsigned &error_status,
                                                          std::string_view &error_info);

  static HttpUrlVerdict evaluate_uncategorized_category_action_policy(HttpProxy *proxy,
                                                                      unsigned &error_status,
                                                                      std::string_view &error_info);

  static std::string_view get_verdict_string(const HttpUrlVerdict verdict);
  static char *get_host_or_ip(char *str, int len, char *buf, gboolean host);
  static char *get_ip(char *s, char *outbuf, int len);
  static char *get_host(char *s, char *outbuf, int len);
  static void tag_result(UrlFilter::Result &result, const HttpUrlCategoryTag tag);
  static char *http_from_url(char *buf, gint size, char *host, const char *file, char* query);

  static void join_urlfilter_results(MergedUrlCategories &merged_categories,
                                     const UrlFilter::Result &result);

  static MergedUrlCategories lookup_categories(HttpProxy *proxy,
                                               UrlFilter *url_filter,
                                               const HttpURL &url_parts,
                                               const UrlLookupMode lookup_mode);

  static std::string get_category_list_string(const MergedUrlCategories &categories);

  static void export_category_list(ZPolicyObj *request_categories,
                                   const MergedUrlCategories &categories);

  bool has_license = false;
  std::atomic_bool is_license_error_logged{false};

  std::unique_ptr<UrlFilter> backend = nullptr;
};

#endif // ZORP_MODULES_HTTPURLFILTER_H_INCLUDED
