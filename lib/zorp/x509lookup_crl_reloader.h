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

#ifndef ZORP_X509LOOKUP_CRL_RELOADER_H_INCLUDED
#define ZORP_X509LOOKUP_CRL_RELOADER_H_INCLUDED

#include <openssl/x509v3.h>
#include <vector>
#include <string>
#include <map>
#include <chrono>
#include <memory>
#include <filesystem>

struct ZProxy;

class X509LookupCrlReloader
{
public:
  X509LookupCrlReloader();
  ~X509LookupCrlReloader();

  X509LookupCrlReloader(const X509LookupCrlReloader &) = delete;
  X509LookupCrlReloader &operator=(const X509LookupCrlReloader &) = delete;
  X509LookupCrlReloader(X509LookupCrlReloader &&) = delete;

  static int crl_new(X509_LOOKUP *ctx);
  static void crl_free(X509_LOOKUP *ctx);
  static int crl_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl, char **ret);
  static int crl_get_by_subject(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, X509_NAME *name, X509_OBJECT *ret);
  X509_LOOKUP_METHOD *get_lookup_method();

  using directories_type = std::vector<std::filesystem::path>;
  void add_directory(const std::filesystem::path &directory);
  directories_type get_directories();

private:
  using X509_OBJECTType = std::unique_ptr<X509_OBJECT, decltype(X509_OBJECT_free)*>;
  static std::filesystem::path create_file_name(const std::filesystem::path &directory, const std::string &extension, unsigned long name_hash);
  static bool file_exists(const std::string &ca_crl, const std::filesystem::path &filename, ZProxy *proxy);
  static bool load_crl_file(X509LookupCrlReloader *lookup_reloader, const std::filesystem::path &path, ZProxy *proxy, X509_LOOKUP *ctx);
  static bool load_cert_file(const std::filesystem::path &path, ZProxy *proxy, X509_LOOKUP *ctx);
  static X509_OBJECT *get_cert_or_crl_object_from_store(X509_STORE *ctx, const X509_OBJECTType &stmp);

  directories_type directories;
  std::map<std::filesystem::path, std::filesystem::file_time_type> last_modification_cache;
  X509_LOOKUP_METHOD *lookup_method = nullptr;
};

#endif
