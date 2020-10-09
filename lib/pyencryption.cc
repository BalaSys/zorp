#include <zorp/pyencryption.h>
#include <zorpll/log.h>

#include <zorp/pyx509.h>
#include <zorp/pyx509chain.h>
#include <zorp/proxyssl.h>
#include <zorp/x509lookup_crl_reloader.h>
#include <openssl/rand.h>
#include <cstring>


static void
z_policy_encryption_free(ZPolicyEncryption *self)
{
  if (self->ssl_client_context)
    {
      SSL_CTX_sess_set_new_cb(self->ssl_client_context, nullptr);
      SSL_CTX_sess_set_remove_cb(self->ssl_client_context, nullptr);
      SSL_CTX_sess_set_get_cb(self->ssl_client_context, nullptr);

      SSL_CTX_free(self->ssl_client_context);
      self->ssl_client_context = nullptr;
    }

  if (self->ssl_server_context)
    {
      SSL_CTX_sess_set_new_cb(self->ssl_server_context, nullptr);
      SSL_CTX_sess_set_remove_cb(self->ssl_server_context, nullptr);

      SSL_CTX_free(self->ssl_server_context);
      self->ssl_server_context = nullptr;
    }


  if (self->x509_lookup_crl_reloader)
    {
      delete self->x509_lookup_crl_reloader;
      self->x509_lookup_crl_reloader = nullptr;
    }

  z_policy_var_unref(self->ssl_opts.ssl_struct);
  self->ssl_opts.ssl_struct = nullptr;

  z_policy_dict_unref(self->ssl_opts.ssl_dict);
  self->ssl_opts.ssl_dict = nullptr;

  self->ob_type->tp_free((PyObject *) self);
}


int
z_policy_encryption_tlsext_servername_cb(SSL *ssl, int * /* _ad */, void * /* _arg */)
{
  ZProxySSLHandshake *handshake = (ZProxySSLHandshake *) SSL_get_app_data(ssl);
  ZProxy *self = handshake->proxy;
  if (self->tls_opts.tlsext_server_host_name->len)
    return SSL_TLSEXT_ERR_OK;

  ZEndpoint side = EP_CLIENT;

  const gchar *server_name;

  g_assert(self);

  z_proxy_enter(self);

  server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

  if (server_name)
    {
      g_string_assign(self->tls_opts.tlsext_server_host_name, server_name);
      z_proxy_log(self, CORE_INFO, 6, "TLS Server Name Indication extension; side='%s', server_name='%s'",
                  EP_STR(side), server_name);
    }

  z_proxy_return(self, SSL_TLSEXT_ERR_OK);
}

static void
z_policy_encryption_log_set_version_error(const char *side, const char *bound)
{
  char buf[128];
  z_log(nullptr, CORE_ERROR, 4, "Error setting %s SSL_CTX %s protocol version; error='%s'",
                                side, bound, z_ssl_get_error_str(buf, sizeof(buf)));
}

static bool
z_policy_encryption_set_methods_and_security(ZPolicyEncryption *self,
                                             const encryption_security_type &client_security, const encryption_security_type &server_security
                                            )
{
  self->ssl_opts.security[EP_CLIENT] = client_security;
  self->ssl_opts.security[EP_SERVER] = server_security;
  static const unsigned char session_id_context[] = "Zorp/TLS";

  if (client_security != ENCRYPTION_SEC_NONE)
    {
      self->ssl_client_context = SSL_CTX_new(TLS_server_method());

      if (!SSL_CTX_set_min_proto_version(self->ssl_client_context, TLS1_VERSION))
        z_policy_encryption_log_set_version_error("client", "min");

      if (!SSL_CTX_set_max_proto_version(self->ssl_client_context, TLS1_3_VERSION))
        z_policy_encryption_log_set_version_error("client", "max");

      SSL_CTX_set_app_data(self->ssl_client_context, self);

      SSL_CTX_set_session_id_context(self->ssl_client_context, session_id_context, sizeof(session_id_context));

      SSL_CTX_set_timeout(self->ssl_client_context, self->ssl_client_context_timeout);
      SSL_CTX_set_tlsext_servername_callback(self->ssl_client_context, z_policy_encryption_tlsext_servername_cb);
    }

  if (server_security != ENCRYPTION_SEC_NONE)
    {
      self->ssl_server_context = SSL_CTX_new(TLS_client_method());

      SSL_CTX_set_app_data(self->ssl_server_context, self);

      if (!SSL_CTX_set_min_proto_version(self->ssl_server_context, TLS1_VERSION))
        z_policy_encryption_log_set_version_error("server", "min");

      if (!SSL_CTX_set_max_proto_version(self->ssl_server_context, TLS1_3_VERSION))
        z_policy_encryption_log_set_version_error("server", "max");


      SSL_CTX_set_timeout(self->ssl_server_context, self->ssl_server_context_timeout);
    }
  return true;
}

/**
 * Export SSL related attributes to Python.
 *
 * @param self          the encryption policy being initialized
 *
 * This function registers all exported SSL attributes with the Python
 * interpreter.
 */
static void
z_policy_encryption_register_vars(ZPolicyEncryption *self)
{
  ZPolicyDict *dict = self->ssl_opts.ssl_dict;

  /* enable ssl */
  z_policy_dict_register(dict, Z_VT_INT, "client_connection_security", Z_VF_READ,
                         &self->ssl_opts.security[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_INT, "server_connection_security", Z_VF_READ,
                         &self->ssl_opts.security[EP_SERVER]);

  /* common members */
  z_policy_dict_register(dict, Z_VT_INT, "handshake_timeout", Z_VF_RW,
                         &self->ssl_opts.handshake_timeout);
  z_policy_dict_register(dict, Z_VT_INT, "handshake_seq", Z_VF_RW,
                         &self->ssl_opts.handshake_seq);

  /* client side */
  z_policy_dict_register(dict, Z_VT_HASH, "client_handshake", Z_VF_READ |  Z_VF_CONSUME,
                         self->ssl_opts.handshake_hash[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_INT, "client_verify_type", Z_VF_RW,
                         &self->ssl_opts.verify_type[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_INT, "client_max_verify_depth", Z_VF_RW,
                         &self->ssl_opts.verify_depth[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_ALIAS, "client_verify_depth", Z_VF_RW,
                         "client_max_verify_depth");
  z_policy_dict_register(dict, Z_VT_STRING, "client_verify_ca_directory",
                         Z_VF_RW | Z_VF_CONSUME,
                         self->ssl_opts.verify_ca_directory[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_STRING, "client_verify_crl_directory",
                         Z_VF_RW | Z_VF_CONSUME,
                         self->ssl_opts.verify_crl_directory[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_INT, "client_permit_invalid_certificates", Z_VF_RW,
                         &self->ssl_opts.permit_invalid_certificates[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_INT, "client_permit_missing_crl", Z_VF_RW,
                         &self->ssl_opts.permit_missing_crl[EP_CLIENT]);

  z_policy_dict_register(dict, Z_VT_INT, "client_disable_proto_tlsv1", Z_VF_RW,
                         &self->ssl_opts.disable_proto_tlsv1[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_INT, "client_disable_proto_tlsv1_1", Z_VF_RW,
                         &self->ssl_opts.disable_proto_tlsv1_1[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_INT, "client_disable_proto_tlsv1_2", Z_VF_RW,
                         &self->ssl_opts.disable_proto_tlsv1_2[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_INT, "client_disable_proto_tlsv1_3", Z_VF_RW,
                         &self->ssl_opts.disable_proto_tlsv1_3[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_INT, "client_disable_compression", Z_VF_RW,
                         &self->ssl_opts.disable_compression[EP_CLIENT]);

  z_policy_dict_register(dict, Z_VT_INT, "client_keypair_generate", Z_VF_RW,
                         &self->ssl_opts.keypair_generate[EP_CLIENT]);

  z_policy_dict_register(dict, Z_VT_STRING, "client_ssl_cipher",
                         Z_VF_RW | Z_VF_CONSUME,
                         self->ssl_opts.ssl_cipher[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_STRING, "client_ciphers_tlsv1_3",
                         Z_VF_RW | Z_VF_CONSUME,
                         self->ssl_opts.ciphers_tlsv1_3[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_STRING, "client_shared_groups",
                         Z_VF_RW | Z_VF_CONSUME,
                         self->ssl_opts.shared_groups[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_INT, "cipher_server_preference", Z_VF_RW,
                         &self->ssl_opts.cipher_server_preference);
  z_policy_dict_register(dict, Z_VT_STRING, "dh_params",
                         Z_VF_RW | Z_VF_CONSUME,
                         self->ssl_opts.dh_params);
  z_policy_dict_register(dict, Z_VT_STRING, "client_ca_hint_directory",
                         Z_VF_RW | Z_VF_CONSUME,
                         self->ssl_opts.ca_hint_directory);
  z_policy_dict_register(dict, Z_VT_INT, "client_disable_send_root_ca", Z_VF_RW,
                         &self->ssl_opts.client_disable_send_root_ca);

  /* server side */
  z_policy_dict_register(dict, Z_VT_HASH, "server_handshake", Z_VF_READ | Z_VF_CONSUME,
                         self->ssl_opts.handshake_hash[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_INT, "server_verify_type", Z_VF_RW,
                         &self->ssl_opts.verify_type[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_INT, "server_max_verify_depth", Z_VF_RW,
                         &self->ssl_opts.verify_depth[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_ALIAS, "server_verify_depth", Z_VF_RW,
                         "server_max_verify_depth");
  z_policy_dict_register(dict, Z_VT_STRING, "server_verify_ca_directory",
                         Z_VF_RW | Z_VF_CONSUME,
                         self->ssl_opts.verify_ca_directory[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_STRING, "server_verify_crl_directory",
                         Z_VF_RW | Z_VF_CONSUME,
                         self->ssl_opts.verify_crl_directory[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_INT, "server_permit_invalid_certificates", Z_VF_RW,
                         &self->ssl_opts.permit_invalid_certificates[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_INT, "server_permit_missing_crl", Z_VF_RW,
                         &self->ssl_opts.permit_missing_crl[EP_SERVER]);

  z_policy_dict_register(dict, Z_VT_INT, "server_disable_proto_tlsv1", Z_VF_RW,
                         &self->ssl_opts.disable_proto_tlsv1[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_INT, "server_disable_proto_tlsv1_1", Z_VF_RW,
                         &self->ssl_opts.disable_proto_tlsv1_1[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_INT, "server_disable_proto_tlsv1_2", Z_VF_RW,
                         &self->ssl_opts.disable_proto_tlsv1_2[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_INT, "server_disable_proto_tlsv1_3", Z_VF_RW,
                         &self->ssl_opts.disable_proto_tlsv1_3[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_INT, "server_disable_compression", Z_VF_RW,
                         &self->ssl_opts.disable_compression[EP_SERVER]);

  z_policy_dict_register(dict, Z_VT_INT, "server_keypair_generate", Z_VF_RW,
                         &self->ssl_opts.keypair_generate[EP_SERVER]);


  z_policy_dict_register(dict, Z_VT_STRING, "server_ssl_cipher",
                         Z_VF_RW | Z_VF_CONSUME,
                         self->ssl_opts.ssl_cipher[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_STRING, "server_ciphers_tlsv1_3",
                         Z_VF_RW | Z_VF_CONSUME,
                         self->ssl_opts.ciphers_tlsv1_3[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_STRING, "server_shared_groups",
                         Z_VF_RW | Z_VF_CONSUME,
                         self->ssl_opts.shared_groups[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_INT, "server_check_subject", Z_VF_RW,
                         &self->ssl_opts.server_check_subject);
  z_policy_dict_register(dict, Z_VT_INT, "disable_renegotiation", Z_VF_RW,
                         &self->ssl_opts.disable_renegotiation);
}

/**
 * Set default values of SSL attributes.
 *
 * @param self          the proxy being initialized
 *
 * The function initializes all SSL related members of the proxy instance.
 */
static void
z_policy_encryption_set_config_defaults(ZPolicyEncryption *self)
{
  self->ssl_client_context = NULL;
  self->ssl_server_context = NULL;

  self->ssl_opts.handshake_timeout = 30000;
  self->ssl_opts.handshake_seq = PROXY_SSL_HS_CLIENT_SERVER;

  for (ZEndpoint side = EP_CLIENT; side < EP_MAX; ++side)
    {
      self->ssl_opts.security[side] = ENCRYPTION_SEC_NONE;
      self->ssl_opts.verify_type[side] = ENCRYPTION_VERIFY_REQUIRED_TRUSTED;
      self->ssl_opts.verify_depth[side] = 4;
      self->ssl_opts.verify_ca_directory[side] = g_string_new("");
      self->ssl_opts.verify_crl_directory[side] = g_string_new("");
      self->ssl_opts.permit_invalid_certificates[side] = FALSE;
      self->ssl_opts.permit_missing_crl[side] = TRUE;
      self->ssl_opts.handshake_hash[side] = g_hash_table_new(g_str_hash, g_str_equal);
      //self->ssl_opts.ssl_cipher[side] = g_string_new("ALL:!aNULL:@STRENGTH");
      self->ssl_opts.ssl_cipher[side] = g_string_new("HIGH:!aNULL:@STRENGTH");
      self->ssl_opts.ciphers_tlsv1_3[side] = g_string_new(
        "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
      );
      self->ssl_opts.shared_groups[side] = g_string_new(
        "X25519:X448:P-521:P-384:P-256"
      );
      self->ssl_opts.disable_proto_tlsv1[side] = FALSE;
      self->ssl_opts.disable_proto_tlsv1_1[side] = FALSE;
      self->ssl_opts.disable_proto_tlsv1_2[side] = FALSE;
      self->ssl_opts.disable_proto_tlsv1_3[side] = TRUE;
      self->ssl_opts.keypair_generate[side] = FALSE;
      self->ssl_opts.disable_compression[side] = FALSE;
    }

  self->ssl_opts.cipher_server_preference = FALSE;
  self->ssl_opts.dh_params = g_string_new("");
  self->ssl_opts.client_disable_send_root_ca = FALSE;

  self->ssl_opts.server_setup_key_cb = NULL;
  self->ssl_opts.server_verify_cert_cb = NULL;

  self->ssl_opts.client_setup_key_cb = NULL;
  self->ssl_opts.client_verify_cert_cb = NULL;

  self->ssl_opts.server_check_subject = TRUE;
  self->ssl_opts.disable_renegotiation = TRUE;
  self->ssl_opts.ca_hint_directory = g_string_new("");

  self->ssl_opts.ssl_dict = z_policy_dict_new();

  z_policy_dict_ref(self->ssl_opts.ssl_dict);
  self->ssl_opts.ssl_struct = z_policy_struct_new(self->ssl_opts.ssl_dict, Z_PST_SHARED);
  g_assert(self->ssl_opts.ssl_struct != NULL);
}

static int
z_policy_encryption_init_instance(ZPolicyEncryption *self, PyObject *args, PyObject *kw_args)
{
  encryption_security_type client_security = ENCRYPTION_SEC_NONE;
  encryption_security_type server_security = ENCRYPTION_SEC_NONE;

  self->ssl_client_context_timeout = 300;
  self->ssl_server_context_timeout = 300;

  const gchar *keywords[] = {
                        "client_security", "server_security",
                        "client_timeout", "server_timeout",
                              NULL
                            };

  if (!PyArg_ParseTupleAndKeywords(args, kw_args,
                                   "|iiii", const_cast<char**>(keywords),
                                   &client_security, &server_security,
                                   &self->ssl_client_context_timeout, &self->ssl_server_context_timeout
                                  ))
    {
      PyErr_SetString(PyExc_TypeError, "Parameters must be int");
      return -1;
    }

  z_policy_encryption_set_config_defaults(self);
  z_policy_encryption_register_vars(self);

  if (!z_policy_encryption_set_methods_and_security(self, client_security, server_security
                                                   ))
    {
      return -1;
    }
  z_log(NULL, CORE_DEBUG, 6, "ZPolicyEncryption created; ");


  self->x509_lookup_crl_reloader = new X509LookupCrlReloader;
  return 0;
}


static void
z_policy_encryption_setup_verify_directories(ZPolicyEncryption *self, SSL_CTX *ctx, ZEndpoint side)
{
  if (self->ssl_opts.verify_ca_directory[side]->len > 0 ||
      self->ssl_opts.verify_crl_directory[side]->len > 0)
    {
      X509_LOOKUP *lookup = X509_STORE_add_lookup(SSL_CTX_get_cert_store(ctx), self->x509_lookup_crl_reloader->get_lookup_method());
      if (self->ssl_opts.verify_ca_directory[side]->len > 0)
        {
          X509_LOOKUP_add_dir(lookup, self->ssl_opts.verify_ca_directory[side]->str, X509_FILETYPE_PEM);
        }
      if (self->ssl_opts.verify_crl_directory[side]->len > 0)
        {
          X509_LOOKUP_add_dir(lookup, self->ssl_opts.verify_crl_directory[side]->str, X509_FILETYPE_PEM);
          X509_STORE_set_flags(SSL_CTX_get_cert_store(ctx), X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
        }
    }
}

static void
z_policy_encryption_setup_ctx_options(ZPolicyEncryption *self, SSL_CTX *ctx, ZEndpoint side)
{
  long options = SSL_OP_ALL |
                      (self->ssl_opts.disable_proto_tlsv1[side] ? SSL_OP_NO_TLSv1 : 0) |
                      (self->ssl_opts.disable_proto_tlsv1_1[side] ? SSL_OP_NO_TLSv1_1 : 0) |
                      (self->ssl_opts.disable_proto_tlsv1_2[side] ? SSL_OP_NO_TLSv1_2 : 0) |
                      (self->ssl_opts.disable_proto_tlsv1_3[side] ? SSL_OP_NO_TLSv1_3 : 0) |
                      (self->ssl_opts.disable_compression[side] ? SSL_OP_NO_COMPRESSION : 0);

  SSL_CTX_set_options(ctx, options);

  if (side == EP_CLIENT)
    {
      SSL_CTX_set_options(ctx, options | (self->ssl_opts.cipher_server_preference ? SSL_OP_CIPHER_SERVER_PREFERENCE : 0));
    }
}

static void
z_policy_encryption_setup_set_verify(ZPolicyEncryption *self, SSL_CTX *ctx, ZEndpoint side)
{
  int verify_mode = 0;
  if (self->ssl_opts.verify_type[side] == ENCRYPTION_VERIFY_REQUIRED_TRUSTED ||
      self->ssl_opts.verify_type[side] == ENCRYPTION_VERIFY_REQUIRED_UNTRUSTED)
    verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  else if (self->ssl_opts.verify_type[side] == ENCRYPTION_VERIFY_OPTIONAL_UNTRUSTED ||
           self->ssl_opts.verify_type[side] == ENCRYPTION_VERIFY_OPTIONAL_TRUSTED)
    verify_mode = SSL_VERIFY_PEER;

  if (verify_mode)
    {
      SSL_CTX_set_verify(ctx, verify_mode, z_proxy_ssl_verify_peer_cert_cb);
    }
}

#include <zorp/pyencryption_private.h>
#include <openssl/err.h>
#include <stdexcept>

template <typename exception_class> void throw_openssl_error()
{
  char buf[256];
  ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
  const char *human_readable_error = buf;
  throw exception_class(human_readable_error);
}

DH_unique_ptr
z_policy_encryption_get_dh_from_pem(const char *buf, int len)
{
  using BIO_deleter =  int (*) (BIO *);
  using BIO_unique_ptr = std::unique_ptr<BIO, BIO_deleter>;

  BIO_unique_ptr bio(BIO_new_mem_buf(const_cast<char *>(buf), len), BIO_free);
  DH_unique_ptr dh(PEM_read_bio_DHparams(bio.get(), NULL, NULL, NULL), DH_free);
  if (!dh)
    throw_openssl_error<std::invalid_argument>();

  return dh;
}

static void
z_policy_encryption_set_dh_params(SSL_CTX *ctx, const ZProxySsl &ssl_opts)
{
  bool is_dh_param_set = (ssl_opts.dh_params->len != 0);
  if (!is_dh_param_set)
    return;

  DH_unique_ptr dh(z_policy_encryption_get_dh_from_pem(ssl_opts.dh_params->str,
                                                       ssl_opts.dh_params->len));
  if (1 != SSL_CTX_set_tmp_dh(ctx, dh.get()))
    throw_openssl_error<std::invalid_argument>();
}

static void
z_policy_encryption_info_callback(const SSL *ssl, int where, int  /* rc */)
{
    ZProxySSLHandshake *handshake = (ZProxySSLHandshake *) SSL_get_app_data(ssl);

    if ((where & SSL_CB_HANDSHAKE_START) && handshake->completed)
      {
        z_proxy_log(handshake->proxy, CORE_ERROR, 3, "Client initiated renegotiation terminated; side='%s'",
                    EP_STR(handshake->side));
        z_stream_shutdown(handshake->proxy->endpoints[handshake->side], SHUT_RDWR, nullptr);
      }
}

static PyObject *
z_policy_encryption_setup_method(ZPolicyEncryption *self, PyObject * /* args */)
{
  for (ZEndpoint side = EP_CLIENT; side < EP_MAX; ++side)
    {
      SSL_CTX *ctx;
      if (side == EP_CLIENT)
        ctx = self->ssl_client_context;
      else
        ctx = self->ssl_server_context;

      if (!ctx)
        continue;

      z_policy_encryption_setup_verify_directories(self, ctx, side);

      if (side == EP_CLIENT && self->ssl_opts.ca_hint_directory->len != 0 &&
          !z_ssl_set_trusted_ca_list(ctx, self->ssl_opts.ca_hint_directory->str))
        {
          z_log(NULL, CORE_ERROR, 1, "Error loading subject names of trusted CA certificates; cadir='%s'",
                self->ssl_opts.ca_hint_directory->str);
        }

      if (!SSL_CTX_set_cipher_list(ctx, self->ssl_opts.ssl_cipher[side]->str))
        {
          z_log(NULL, CORE_ERROR, 1, "Error setting cipher spec; ciphers='%s', side='%s'",
                      self->ssl_opts.ssl_cipher[side]->str, EP_STR(side));

          Py_RETURN_FALSE;
        }

      if (!SSL_CTX_set_ciphersuites(ctx, self->ssl_opts.ciphers_tlsv1_3[side]->str))
        {
          z_log(NULL, CORE_ERROR, 1, "Error setting TLSv1.3 cipher spec; ciphers='%s', side='%s'",
                      self->ssl_opts.ciphers_tlsv1_3[side]->str, EP_STR(side));

          Py_RETURN_FALSE;
        }

      if (!SSL_CTX_set1_groups_list(ctx, self->ssl_opts.shared_groups[side]->str))
        {
          z_log(NULL, CORE_ERROR, 1, "Error setting supported shared groups list; groups='%s', side='%s'",
                      self->ssl_opts.shared_groups[side]->str, EP_STR(side));

          Py_RETURN_FALSE;
        }

      if (self->ssl_opts.disable_renegotiation && side == EP_CLIENT)
        SSL_CTX_set_info_callback(ctx, z_policy_encryption_info_callback);


      z_policy_encryption_setup_ctx_options(self, ctx, side);
      z_policy_encryption_setup_set_verify(self, ctx, side);

      switch (side)
        {
        case EP_CLIENT:
          try
            {
              z_policy_encryption_set_dh_params(ctx, self->ssl_opts);
            }
          catch (const std::invalid_argument &e)
            {
              z_log(NULL, CORE_ERROR, 1,
                    "Error setting DH parameters for ephemeral DH key; side='%s', error='%s'",
                     EP_STR(side), e.what());
              Py_RETURN_FALSE;
            }
        break;

        case EP_SERVER:
          SSL_CTX_set_client_cert_cb(ctx, z_proxy_ssl_client_cert_cb); /* instead of specifying key here */
          break;

        case EP_MAX:
          abort();
        break;
        }

      /* For server side, the z_proxy_ssl_app_verify_callback_cb sets up
         trusted CA list. It calls verify_cert callback for both sides.

         Releasing the handshake reference is done by the callback. */

      SSL_CTX_set_cert_verify_callback(ctx, z_proxy_ssl_app_verify_cb, nullptr);
    }

  Py_RETURN_TRUE;
}

static PyMethodDef z_policy_encryption_methods[] =
{
  { "setup",       (PyCFunction) z_policy_encryption_setup_method, 0, NULL },
  { NULL,          NULL, 0, NULL }   /* sentinel*/
};

static PyObject *
z_policy_encryption_getattro(ZPolicyEncryption *self, PyObject *name_obj)
{
  g_assert(PyString_Check(name_obj));

  const gchar *name = PyString_AS_STRING(name_obj);

  if (strcmp(name, "settings") == 0)
    {
      if (self->ssl_opts.ssl_struct)
        {
          z_policy_var_ref(self->ssl_opts.ssl_struct);
          return self->ssl_opts.ssl_struct;
        }
    }

  return PyObject_GenericGetAttr((PyObject *) self, name_obj);
}

PyTypeObject z_policy_encryption_type =
{
  PyObject_HEAD_INIT(&PyType_Type)
  0,                                          /* ob_size */
  "ZPolicyEncryption",                        /* tp_name */
  sizeof(ZPolicyEncryption),                  /* tp_basicsize */
  0,                                          /* tp_itemsize */
  (destructor) z_policy_encryption_free,      /* tp_dealloc */
  0,                                          /* tp_print */
  0, /* tp_getattr */
  0, /* tp_setattr */
  0, /* tp_compare */
  0, /* tp_repr */
  0, /* tp_as_number */
  0, /* tp_as_sequence */
  0, /* tp_as_mapping */
  0, /* tp_hash */
  0, /* tp_call */
  0, /* tp_str */
  (getattrofunc) z_policy_encryption_getattro, /* tp_getattro */
  0, /* tp_setattro */
  0, /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
  "ZPolicyEncryption class for Zorp", /* documentation string */
/*  0, 0, 0, 0,
  Z_PYTYPE_TRAILER*/
  NULL,                                   /* tp_traverse */
  NULL,                                   /* tp_clear */
  NULL,                                   /* tp_reachcompare */
  0,                                      /* tp_weaklistoffset */
  NULL,                                   /* tp_iter */
  NULL,                                   /* tp_iternext */
  z_policy_encryption_methods,            /* tp_methods */
  NULL,                                   /* tp_members */
  NULL,                                   /* tp_getset */
  NULL,                                   /* tp_base */
  NULL,                                   /* tp_dict */
  NULL,                                   /* tp_descr_get */
  NULL,                                   /* tp_descr_set */
  0,                                      /* tp_dictoffset */
  (initproc) z_policy_encryption_init_instance,/* tp_init */
  NULL,                                   /* tp_alloc */
  PyType_GenericNew,                      /* tp_new */
  NULL,                                   /* tp_free */
  NULL,                                   /* tp_is_gc */
  NULL,                                   /* tp_bases */
  NULL,                                   /* tp_mro */
  NULL,                                   /* tp_cache */
  NULL,                                   /* tp_subclasses */
  NULL,                                   /* tp_weaklist */
  NULL,                                   /* tp_del */
  0,                                      /* tp_version_tag */
};

bool
z_policy_encryption_type_check(PyObject *ob)
{
  return ob->ob_type == &z_policy_encryption_type ||
         PyType_IsSubtype(ob->ob_type, &z_policy_encryption_type);
}

/**
 * z_policy_encryption_module_init:
 *
 * Module initialisation
 */
void
z_policy_encryption_module_init(void)
{
  PyObject *m;
  void *o;

  if (PyType_Ready(&z_policy_encryption_type) < 0)
    g_assert_not_reached();

  m = PyImport_AddModule("Zorp.Encryption_");
  Py_INCREF(&z_policy_encryption_type);
  o = &z_policy_encryption_type;
  PyModule_AddObject(m, "Encryption", (PyObject *) o);
}
