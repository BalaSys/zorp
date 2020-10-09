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

#include <zorp/certchain.h>

ZCertificateChain *
z_certificate_chain_new(void)
{
  ZCertificateChain *self = Z_NEW_COMPAT(Z_CLASS(ZCertificateChain), ZCertificateChain);

  self->chain = sk_X509_new_null();

  return self;
}

int
z_certificate_chain_set_cert(ZCertificateChain *self, X509 *cert)
{
  if (self->cert)
    X509_free(self->cert);

  self->cert = cert;
  return X509_up_ref(cert);
}

int
z_certificate_chain_add_cert_to_chain(ZCertificateChain *self, X509 *cert)
{
  if (!sk_X509_push(self->chain, cert))
    return 0;

  return X509_up_ref(cert);
}

X509 *
z_certificate_chain_get_cert_from_chain(ZCertificateChain *self, gint idx)
{
  return sk_X509_value(self->chain, idx);
}

static void
z_certificate_chain_free_method(ZObject *s)
{
  ZCertificateChain *self = Z_CAST(s, ZCertificateChain);
  if (self->cert)
    X509_free(self->cert);
  sk_X509_pop_free(self->chain, X509_free);
  z_object_free_method(s);
}

ZObjectFuncs z_certificate_chain_funcs =
{
  Z_FUNCS_COUNT(ZObject),
  z_certificate_chain_free_method,
};

Z_CLASS_DEF(ZCertificateChain, ZObject, z_certificate_chain_funcs);
