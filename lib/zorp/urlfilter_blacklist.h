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

#ifndef ZORP_URLFILTER_BLACKLIST_H_INCLUDED
#define ZORP_URLFILTER_BLACKLIST_H_INCLUDED

#define FORMAT_MAGIC 0x5A554646
#define FORMAT_VERSION 4

#include <memory>

#include <zorp/zorp.h>
#include <zorp/urlfilter.h>
#include <glib.h>

class ZBLTreeData final
{
public:
  ZBLTreeData() = default;
  ~ZBLTreeData();

  ZBLTreeData(const ZBLTreeData &) = delete;
  ZBLTreeData &operator=(const ZBLTreeData &) = delete;
  ZBLTreeData(ZBLTreeData &&) = delete;
  ZBLTreeData &operator=(ZBLTreeData &&) = delete;

  std::int8_t *data = nullptr;
  std::int32_t size = 0;

  GTree *categories = nullptr;

  std::int8_t *mmap_addr = nullptr;
  std::size_t mmap_size = 0;

  dev_t st_dev;
  ino_t st_inode;
};

class UrlFilterBlacklist : public UrlFilter
{
public:
  UrlFilterBlacklist();
  virtual ~UrlFilterBlacklist();

  virtual Result lookup_url(std::string_view url) override;

private:
  Result z_bl_lookup(const gchar *key);
  std::unique_ptr<ZBLTreeData> z_bl_tree_load(const gchar *filename);
  Result z_bl_tree_match(const ZBLTreeData *tree, const gchar *key);
};

#endif
