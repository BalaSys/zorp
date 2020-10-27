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

#ifndef ZORP_URLFILTER_H_INCLUDED
#define ZORP_URLFILTER_H_INCLUDED

#include <array>
#include <string>
#include <string_view>

#include <zorpll/zmap.h>

using namespace std::literals;

enum class HttpUrlCategoryTag
{
  URL,
  IP,
  REVERSE_HOSTNAME,
};

static constexpr auto httpurlcategorytag_strings = make_z_map(
  std::make_pair(HttpUrlCategoryTag::URL,              "URL"sv),
  std::make_pair(HttpUrlCategoryTag::IP,               "IP address of server"sv),
  std::make_pair(HttpUrlCategoryTag::REVERSE_HOSTNAME, "reverse lookup for the IP address of server"sv)
);

class UrlFilter
{
public:
  static constexpr int MAX_CATEGORIES = 5;
  struct Result
  {
    std::array<std::string, MAX_CATEGORIES> category = {};
    std::array<HttpUrlCategoryTag, MAX_CATEGORIES> category_tag = {};
    unsigned num_categories = 0;
  };

  UrlFilter() = default;
  virtual ~UrlFilter() = default;

  virtual Result lookup_url(std::string_view url) = 0;

  bool is_initialized() const;

protected:
  bool initialized = false;
};

#endif
