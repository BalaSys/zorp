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

#ifndef ZORP_MODULES_HTTP_URL_FILTER_H_INCLUDED
#define ZORP_MODULES_HTTP_URL_FILTER_H_INCLUDED

#include "http.h"

#include <string_view>

void http_url_filter_set_license_state(bool has_license);
void http_url_filter_init();
gboolean http_url_filter(HttpProxy *self, std::string_view url_str, const HttpURL &url_parts);

#endif // ZORP_MODULES_HTTP_URL_FILTER_H_INCLUDED
