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

#include <zorp/x509lookup_crl_reloader.h>
#include <zorp/proxy.h>
#include <iostream>
#include <cstring>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <filesystem>

/* 0x1010103fL is OpenSSL 1.1.1c
 *
 * After Ubuntu Bionic updated thear OpenSSL version to 1.1.1c, this code
 * must be removed.
 */
#if OPENSSL_VERSION_NUMBER < 0x1010103fL
struct x509_object_st {
    /* one of the above types */
    X509_LOOKUP_TYPE type;
    union {
        char *ptr;
        X509 *x509;
        X509_CRL *crl;
        EVP_PKEY *pkey;
    } data;
};
#endif


/* 0x1010009fL is OpenSSL 1.1.0i
 * Only this version contains the API we need here.
 *
 * After Ubuntu Bionic updated their OpenSSL version to 1.1.0i, this code
 * must be removed.
*/
#if OPENSSL_VERSION_NUMBER < 0x1010009fL
struct x509_lookup_method_st {
    const char *name;
    int (*new_item) (X509_LOOKUP *ctx);
    void (*free) (X509_LOOKUP *ctx);
    int (*init) (X509_LOOKUP *ctx);
    int (*shutdown) (X509_LOOKUP *ctx);
    int (*ctrl) (X509_LOOKUP *ctx, int cmd, const char *argc, long argl,
                 char **ret);
    int (*get_by_subject) (X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                           X509_NAME *name, X509_OBJECT *ret);
    int (*get_by_issuer_serial) (X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                                 X509_NAME *name, ASN1_INTEGER *serial,
                                 X509_OBJECT *ret);
    int (*get_by_fingerprint) (X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                               const unsigned char *bytes, int len,
                               X509_OBJECT *ret);
    int (*get_by_alias) (X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                         const char *str, int len, X509_OBJECT *ret);
};

struct x509_lookup_st {
    int init;                   /* have we been started */
    int skip;                   /* don't use us. */
    X509_LOOKUP_METHOD *method; /* the functions */
    char *method_data;          /* method data */
    X509_STORE *store_ctx;      /* who owns us */
};

static X509_LOOKUP_METHOD x509_crl_reloader = {
   "CRL file reloader",
   X509LookupCrlReloader::crl_new,            /* new */
   X509LookupCrlReloader::crl_free,           /* free */
   NULL,                        /* init */
   NULL,                        /* shutdown */
   X509LookupCrlReloader::crl_ctrl,           /* ctrl */
   X509LookupCrlReloader::crl_get_by_subject, /* get_by_subject */
   NULL,                        /* get_by_issuer_serial */
   NULL,                        /* get_by_fingerprint */
   NULL                         /* get_by_alias */
};

static X509_LOOKUP_METHOD *X509_LOOKUP_meth_new(const char *name)
{
  return &x509_crl_reloader;
}

static void X509_LOOKUP_meth_free(X509_LOOKUP_METHOD *method)
{
  return;
}

static int X509_LOOKUP_meth_set_new_item(X509_LOOKUP_METHOD *method,
                                  int (*new_item) (X509_LOOKUP *ctx))
{
  return 0;
}

static int X509_LOOKUP_meth_set_free(
    X509_LOOKUP_METHOD *method,
    void (*free) (X509_LOOKUP *ctx))
{
  return 0;
}

static int X509_LOOKUP_meth_set_ctrl(
    X509_LOOKUP_METHOD *method,
    int (*X509_LOOKUP_ctrl_fn)(X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **ret))
{
  return 0;
}

static int X509_LOOKUP_meth_set_get_by_subject(X509_LOOKUP_METHOD *method,
    int (*X509_LOOKUP_get_by_subject_fn)(X509_LOOKUP *ctx,
                                              X509_LOOKUP_TYPE type,
                                              X509_NAME *name,
                                              X509_OBJECT *ret))
{
  return 0;
}

static int X509_LOOKUP_set_method_data(X509_LOOKUP *ctx, void *data)
{
    ctx->method_data = static_cast<char*>(data);
    return 1;
}

void *X509_LOOKUP_get_method_data(const X509_LOOKUP *ctx)
{
    return ctx->method_data;
}

static void x509_object_free_internal(X509_OBJECT *a)
{
     if (a == NULL)
         return;
     switch (a->type) {
     default:
         break;
     case X509_LU_X509:
         X509_free(a->data.x509);
         break;
     case X509_LU_CRL:
         X509_CRL_free(a->data.crl);
         break;
     }
}

static int X509_OBJECT_set1_X509(X509_OBJECT *a, X509 *obj)
{
    if (a == NULL || !X509_up_ref(obj))
        return 0;

    x509_object_free_internal(a);
    a->type = X509_LU_X509;
    a->data.x509 = obj;
    return 1;
}

static int X509_OBJECT_set1_X509_CRL(X509_OBJECT *a, X509_CRL *obj)
{
    if (a == NULL || !X509_CRL_up_ref(obj))
        return 0;

    x509_object_free_internal(a);
    a->type = X509_LU_CRL;
    a->data.crl = obj;
    return 1;
}

static X509_STORE *X509_LOOKUP_get_store(const X509_LOOKUP *ctx)
{
    return ctx->store_ctx;
}
#endif

X509LookupCrlReloader::X509LookupCrlReloader()
{
  lookup_method = X509_LOOKUP_meth_new("CRL file reloader");
  X509_LOOKUP_meth_set_new_item(lookup_method, X509LookupCrlReloader::crl_new);
  X509_LOOKUP_meth_set_free(lookup_method, X509LookupCrlReloader::crl_free);
  X509_LOOKUP_meth_set_ctrl(lookup_method, X509LookupCrlReloader::crl_ctrl);
  X509_LOOKUP_meth_set_get_by_subject(lookup_method, X509LookupCrlReloader::crl_get_by_subject);
}

X509LookupCrlReloader::~X509LookupCrlReloader()
{
  X509_LOOKUP_meth_free(lookup_method);
}

X509_LOOKUP_METHOD *
X509LookupCrlReloader::get_lookup_method()
{
  return lookup_method;
}

int
X509LookupCrlReloader::crl_new(X509_LOOKUP *ctx)
{
   X509LookupCrlReloader *data = new X509LookupCrlReloader();

   X509_LOOKUP_set_method_data(ctx, data);

   return 1;
}

void
X509LookupCrlReloader::crl_free(X509_LOOKUP *ctx)
{
   X509LookupCrlReloader *data = reinterpret_cast<X509LookupCrlReloader*>(X509_LOOKUP_get_method_data(ctx));

  if (!data)
    return;

  delete data;
}

int
X509LookupCrlReloader::crl_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl, char **ret)
{
  X509LookupCrlReloader *lookup_reloader = reinterpret_cast<X509LookupCrlReloader*>(X509_LOOKUP_get_method_data(ctx));

  switch (cmd)
    {
      case X509_L_ADD_DIR:
        lookup_reloader->add_directory(std::filesystem::path(argp));
        break;
      default:
       break;
    }

  return 1;
}

std::filesystem::path
X509LookupCrlReloader::create_file_name(const std::filesystem::path &directory, const std::string &extension, unsigned long name_hash)
{
  constexpr int hash_length = 8;
  constexpr int max_extension_length = 3;
  constexpr int null_terminator_length = 1;
  std::array<char, hash_length + max_extension_length + null_terminator_length> filename;

  std::snprintf(&filename[0], filename.size(), "%08lx%s", name_hash, extension.c_str());

  std::filesystem::path path = directory / std::filesystem::path(filename.begin());

  return path;
}

bool
X509LookupCrlReloader::load_crl_file(X509LookupCrlReloader *lookup_reloader, const std::filesystem::path &path, ZProxy *proxy, X509_LOOKUP *ctx)
{
  std::filesystem::file_time_type file_modification_time = std::filesystem::last_write_time(path);

  auto emplaced_value = lookup_reloader->last_modification_cache.emplace(path, file_modification_time);
  if (!emplaced_value.second)
    {
      bool is_modification_time_the_same = (*emplaced_value.first).second == file_modification_time;
      if (is_modification_time_the_same)
        {
          z_proxy_log(proxy, CORE_INFO, 4, "CRL file did not change since last check, not reloading; filename='%s'", path.c_str());
          return false;
        }
      else
        {
          z_proxy_log(proxy, CORE_INFO, 3, "CRL file changed since last check, reloading; filename='%s'", path.c_str());
          (*emplaced_value.first).second = file_modification_time;
        }
    }

  if ((X509_load_crl_file(ctx, path.c_str(), X509_FILETYPE_PEM)) == 0)
    {
      z_proxy_log(proxy, CORE_ERROR, 3, "Error loading CRL file; filename='%s', error='%s'", path.c_str(), ERR_error_string(ERR_get_error(), nullptr));
      return false;
    }

  return true;
}

bool
X509LookupCrlReloader::load_cert_file(const std::filesystem::path &path, ZProxy *proxy, X509_LOOKUP *ctx)
{
  if ((X509_load_cert_file(ctx, path.c_str(), X509_FILETYPE_PEM)) == 0)
    {
      z_proxy_log(proxy, CORE_ERROR, 3, "Error loading certificate file; filename='%s', error='%s'", path.c_str(), ERR_error_string(ERR_get_error(), nullptr));
      return false;
    }

  return true;
}

bool
X509LookupCrlReloader::file_exists(const std::string &ca_crl, const std::filesystem::path &path, ZProxy *proxy)
{
  std::error_code error_code;
  bool exists = std::filesystem::exists(path, error_code);
  if (error_code || !exists)
    {
      z_proxy_log(proxy, CORE_DEBUG, 4, "Searched %s file does not exist; filename='%s'", ca_crl.c_str(), path.c_str());
      return false;
    }

  z_proxy_log(proxy, CORE_DEBUG, 6, "Searched %s file exists; filename='%s'", ca_crl.c_str(), path.c_str());
  return true;
}

X509_OBJECT *
X509LookupCrlReloader::get_cert_or_crl_object_from_store(X509_STORE *x509_store, const X509_OBJECTType &stmp)
{
  X509_OBJECT *object = nullptr;
  X509_STORE_lock(x509_store);
  int index = sk_X509_OBJECT_find(X509_STORE_get0_objects(x509_store), stmp.get());
  if (index != -1)
    {
      object = sk_X509_OBJECT_value(X509_STORE_get0_objects(x509_store), index);
    }
  X509_STORE_unlock(x509_store);

  return object;
}

int
X509LookupCrlReloader::crl_get_by_subject(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, X509_NAME *name, X509_OBJECT *ret)
{
  std::string extension;
  std::string ca_crl;
  X509_OBJECTType stmp {
    X509_OBJECT_new(),
    X509_OBJECT_free
  };

  switch (type)
    {
      case X509_LU_X509:
        {
          extension=".0";
          std::unique_ptr<X509, decltype(X509_free)*> x509 {
            X509_new(),
            X509_free
          };
          X509_set_subject_name(x509.get(), name);
          X509_OBJECT_set1_X509(stmp.get(), x509.get());
          ca_crl = "ca";
          break;
        }
      case X509_LU_CRL:
        {
          extension=".r0";
          std::unique_ptr<X509_CRL, decltype(X509_CRL_free) *> crl {
            X509_CRL_new(),
            X509_CRL_free
          };
          X509_CRL_set_issuer_name(crl.get(), name);
          X509_OBJECT_set1_X509_CRL(stmp.get(), crl.get());
          ca_crl = "crl";
          break;
        }
      default:
        X509err(X509_F_GET_CERT_BY_SUBJECT,X509_R_WRONG_LOOKUP_TYPE);
        return 0;
    }

  X509_STORE *x509_store = X509_LOOKUP_get_store(ctx);
  ZProxy *self = reinterpret_cast<ZProxy *>(X509_STORE_get_ex_data(x509_store, 0));

  unsigned long name_hash = X509_NAME_hash(name);
  X509LookupCrlReloader *lookup_reloader = reinterpret_cast<X509LookupCrlReloader*>(X509_LOOKUP_get_method_data(ctx));
  for (const auto &directory : lookup_reloader->get_directories())
    {
      std::filesystem::path path = create_file_name(directory, extension, name_hash);
      if (!file_exists(ca_crl, path, self))
        continue;
      if (type == X509_LU_CRL)
        {
          if (!load_crl_file(lookup_reloader, path, self, ctx))
            continue;
        }
      else
        {
          if (!load_cert_file(path, self, ctx))
            continue;
        }
    }

  X509_OBJECT *tmp_obj = get_cert_or_crl_object_from_store(x509_store, stmp);
  if (!tmp_obj)
    return 0;

/*
 * This HACK is needed because OpenSSL has a bug which causes a crash.
 * X509_OBJECT_set1_X509 function calls x509_object_free_internal if
 * the type is not X509_LU_NONE. The ret object is a stack allocated
 * variable coming from OpenSSL's code thus freeing it causes the crash.
 *
 * https://github.com/openssl/openssl/issues/8673
 * https://github.com/openssl/openssl/commit/b926f9deb3dc79d00f0a989370e95867516a3a17
 */
#if OPENSSL_VERSION_NUMBER < 0x1010103fL
  static_cast<x509_object_st*>(ret)->type = X509_LU_NONE;
#endif

  if (type == X509_LU_X509)
    X509_OBJECT_set1_X509(ret, X509_OBJECT_get0_X509(tmp_obj));
  else
    X509_OBJECT_set1_X509_CRL(ret, X509_OBJECT_get0_X509_CRL(tmp_obj));

  return 1;
}

void
X509LookupCrlReloader::add_directory(const std::filesystem::path &directory)
{
  directories.push_back(directory);
}

X509LookupCrlReloader::directories_type
X509LookupCrlReloader::get_directories()
{
  return directories;
}
