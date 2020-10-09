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

#ifndef ZORP_PYENCRYPTION_H_INCLUDED
#define ZORP_PYENCRYPTION_H_INCLUDED

#include <zorp/pystruct.h>
#include <zorpll/ssl.h>
#include <zorp/certchain.h>
#include <zorp/proxycommon.h>
#include <zorpll/sockaddr.h>
#include <openssl/ssl.h>
#include <chrono>
#include <array>
#include <map>
#include <string>
#include <zorp/x509lookup_crl_reloader.h>

typedef enum
{
  ENCRYPTION_SEC_NONE                    = 0,
  ENCRYPTION_SEC_FORCE_SSL               = 1,
  ENCRYPTION_SEC_ACCEPT_STARTTLS         = 2,
  ENCRYPTION_SEC_FORWARD_STARTTLS        = 3,
} encryption_security_type;

typedef enum
{
  ENCRYPTION_VERIFY_NONE                = 0,
  ENCRYPTION_VERIFY_OPTIONAL_UNTRUSTED  = 1,
#define ENCRYPTION_VERIFY_OPTIONAL ENCRYPTION_VERIFY_OPTIONAL_UNTRUSTED
  ENCRYPTION_VERIFY_OPTIONAL_TRUSTED    = 2,
  ENCRYPTION_VERIFY_REQUIRED_UNTRUSTED  = 3,
  ENCRYPTION_VERIFY_REQUIRED_TRUSTED    = 4,
} proxy_ssl_verify_type;

class SessionTicketKey
{
public:
  SessionTicketKey() : is_set(false)
    {};
  SessionTicketKey(const std::array<unsigned char, 16> &hmac_key, const std::array<unsigned char, 16> &aes_key, const std::array<unsigned char, 16> key_name, int timeout) : hmac_key(hmac_key), aes_key(aes_key), key_name(key_name), is_set(true)
    {
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
      encrypt_expire_time = now + std::chrono::duration<int>(timeout);
      decrypt_expire_time = now + std::chrono::duration<int>(timeout) + std::chrono::duration<int>(timeout);
    };
  bool can_be_used_to_encrypt()
    {
      return (is_set && encrypt_expire_time >= std::chrono::steady_clock::now());
    }
  bool can_be_used_to_decrypt()
    {
      return (is_set && decrypt_expire_time >= std::chrono::steady_clock::now());
    }
  unsigned char *get_key_name()
    {
      return key_name.data();
    }
  unsigned char *get_aes_key()
    {
      return aes_key.data();
    }
  unsigned char *get_hmac_key()
    {
      return hmac_key.data();
    }
  bool find_key(const std::array<unsigned char, 16> &other_key_name)
    {
      return key_name == other_key_name;
    }
private:
  std::array<unsigned char, 16> hmac_key;
  std::array<unsigned char, 16> aes_key;
  std::array<unsigned char, 16> key_name;
  std::chrono::steady_clock::time_point encrypt_expire_time, decrypt_expire_time;
  bool is_set;
};

typedef struct _ZProxySsl {
  ZPolicyDict *ssl_dict;
  ZPolicyObj *ssl_struct;

  encryption_security_type security[EP_MAX];

  GString *ssl_cipher[EP_MAX];
  GString *ciphers_tlsv1_3[EP_MAX];
  GString *shared_groups[EP_MAX];

  ZPolicyObj *server_setup_key_cb, *server_verify_cert_cb;
  ZPolicyObj *client_setup_key_cb, *client_verify_cert_cb;

  GString *verify_ca_directory[EP_MAX];
  GString *verify_crl_directory[EP_MAX];

  gint handshake_timeout;
  gint handshake_seq;
  GHashTable *handshake_hash[EP_MAX];

  proxy_ssl_verify_type verify_type[EP_MAX];
  int verify_depth[EP_MAX];
  gboolean disable_proto_tlsv1[EP_MAX];
  gboolean disable_proto_tlsv1_1[EP_MAX];
  gboolean disable_proto_tlsv1_2[EP_MAX];
  gboolean disable_proto_tlsv1_3[EP_MAX];
  gboolean keypair_generate[EP_MAX];
  gboolean cipher_server_preference;
  gboolean disable_compression[EP_MAX];

  gboolean permit_invalid_certificates[EP_MAX];
  gboolean permit_missing_crl[EP_MAX];
  gboolean server_check_subject;
  gboolean disable_renegotiation;
  gboolean client_disable_send_root_ca;

  GString *dh_params;
  GString *ca_hint_directory;

} ZProxySsl;

typedef struct _ZPolicyEncryption
{
  PyObject_HEAD
  SSL_CTX *ssl_client_context;
  long ssl_client_context_timeout;
  SSL_CTX *ssl_server_context;
  long ssl_server_context_timeout;

  ZProxySsl ssl_opts;
  X509LookupCrlReloader *x509_lookup_crl_reloader;
} ZPolicyEncryption;

std::string z_policy_encryption_get_server_cache_key(ZProxy *self);

extern PyTypeObject z_policy_encryption_type;

bool z_policy_encryption_type_check(PyObject *ob);

void z_policy_encryption_module_init(void);

#endif
