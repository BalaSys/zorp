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

#include <zorp/pyx509.h>
#include <zorp/zpython.h>
#include <zorp/pystruct.h>

#include <zorpll/log.h>

#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <set>
#include <string>

#define PROXY_SSL_EXTRACT_PEM(s, l, r) \
  ({ void *p; BIO *bio = BIO_new_mem_buf(s, l); p = r(bio, NULL, NULL, NULL); BIO_free(bio); p; })

typedef struct _ZorpCertificate
{
  PyObject_HEAD
  X509 *cert;
} ZorpCertificate;

static void z_py_zorp_certificate_free(ZorpCertificate *self);
static PyObject *z_py_zorp_certificate_getattr(PyObject *o, char *name);
static PyTypeObject z_py_zorp_certificate_type =
{
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "Zorp Certificate",
  sizeof(ZorpCertificate),
  0,
  (destructor) z_py_zorp_certificate_free,
  0,                                  /* tp_print */
  z_py_zorp_certificate_getattr,      /* tp_getattr */
  0,                                  /* tp_setattr */
  0,                                  /* tp_compare */
  0,                                  /* tp_repr */
  0,                                  /* tp_as_number */
  0,                                  /* tp_as_sequence */
  0,                                  /* tp_as_mapping */
  0,                                  /* tp_hash */
  0,                                  /* tp_call */
  0,                                  /* tp_str */
  0,                                  /* tp_getattro */
  0,                                  /* tp_setattro */
  0,                                  /* tp_as_buffer */
  0,                                  /* flags */
  "ZorpCertificate class for Zorp",   /* docstring */
  0, 0, 0, 0,
  Z_PYTYPE_TRAILER
};


static PyObject *
z_py_zorp_certificate_new(X509 *cert)
{
  ZorpCertificate *self;

  if (!cert)
    return z_policy_none_ref();

  self = PyObject_New(ZorpCertificate, &z_py_zorp_certificate_type);
  self->cert = cert;

  if (!X509_up_ref(cert))
    {
      PyErr_SetString(PyExc_RuntimeError, "X509_up_ref failed.");
      return z_policy_none_ref();
    }

  return (PyObject *) self;
}

static PyObject *
z_py_zorp_certificate_getattr(PyObject *o, char *name)
{
  ZorpCertificate *self = (ZorpCertificate *) o;
  PyObject *res = NULL;
  BIO *bio;
  guint len;
  gchar *mem;
  gchar buf[512];

  if (strcmp(name, "blob") == 0)
    {
      bio = BIO_new(BIO_s_mem());

      PEM_write_bio_X509(bio, self->cert);
      len = BIO_get_mem_data(bio, &mem);
      res = PyString_FromStringAndSize(mem, len);

      BIO_free(bio);
    }
  else if (strcmp(name, "issuer") == 0)
    {
      X509_NAME_oneline(X509_get_issuer_name(self->cert), buf, sizeof(buf));
      res = PyString_FromString(buf);
    }
  else if (strcmp(name, "subject") == 0)
    {
      X509_NAME_oneline(X509_get_subject_name(self->cert), buf, sizeof(buf));
      res = PyString_FromString(buf);
    }
  else if (strcmp(name, "serial") == 0)
    {
      BIGNUM *serial_bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(self->cert), NULL);
      char *serial_string = BN_bn2hex(serial_bn);
      res = PyInt_FromString(serial_string, nullptr, 16);
      OPENSSL_free(serial_string);
      BN_free(serial_bn);
    }
  else
    {
      PyErr_SetString(PyExc_AttributeError, "Attribute not found");
    }
  return res;
}

static void
z_py_zorp_certificate_free(ZorpCertificate *self)
{
  X509_free(self->cert);
  PyObject_Del(self);
}

static void
zorp_certificate_delete_extensions(X509 *certificate, std::set<std::string> white_list_set)
{
  int extension_location = 0;
  while (extension_location < X509_get_ext_count(certificate))
    {
      X509_EXTENSION *ext = X509_get_ext(certificate, extension_location);
      ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
      std::string extension_name(OBJ_nid2sn(OBJ_obj2nid(obj)));

      if (white_list_set.find(extension_name) == white_list_set.end())
        {
          X509_EXTENSION *return_ext = X509_delete_ext(certificate, extension_location);
          X509_EXTENSION_free(return_ext);
          extension_location--;
        }
      extension_location++;
    }
}

static void
zorp_certificate_fix_key_usage(X509 *certificate)
{
  ASN1_BIT_STRING *usage;
  int usage_crit;
  if ((usage = (ASN1_BIT_STRING *)X509_get_ext_d2i(certificate, NID_key_usage, &usage_crit, NULL)))
    {
      char16_t usage_data = 0;
      if (usage->length > 0)
        {
          usage_data = usage->data[0];
          if (usage->length > 1)
          {
            usage_data |= usage->data[1] << 8;
          }
        }
      usage_data |= KU_KEY_ENCIPHERMENT | KU_DIGITAL_SIGNATURE;
      unsigned char usage_data_bytes[2] = {(unsigned char)usage_data, (unsigned char)(usage_data >> 8)};
      ASN1_OCTET_STRING_set(usage, usage_data_bytes, 2);
      X509_add1_ext_i2d(certificate, NID_key_usage, usage, usage_crit, X509V3_ADD_REPLACE);
    }
}

static ZPolicyObj *
z_py_zorp_certificate_handle_extensions(gpointer user_data, ZPolicyObj *args, ZPolicyObj * /* kw */)
{
  X509 *certificate = (X509 *) user_data;
  ZPolicyObj *white_list;

  if (!z_policy_var_parse(args, "(O)", &white_list))
    {
      PyErr_SetString(PyExc_ValueError, "Argument must be a list containing strings(white_list)");
      return nullptr;
    }

  if (z_policy_seq_length(white_list) == 0)
    return z_policy_none_ref();

  std::set<std::string> white_list_set;

  for (int i = 0; i < z_policy_seq_length(white_list); i++)
    {
      ZPolicyObj *element = z_policy_seq_getitem(white_list, i);
      const char *string_element = PyString_AsString(element);
      if (!string_element)
        {
          PyErr_SetString(PyExc_ValueError, "white_list must contain strings");
          return nullptr;
        }
      white_list_set.emplace(string_element);
    }

  zorp_certificate_delete_extensions(certificate, white_list_set);

  zorp_certificate_fix_key_usage(certificate);

  // Let OpenSSL know that it needs to re_encode.
  i2d_re_X509_tbs(certificate, NULL);

  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(bio, certificate);
  gchar *mem;
  guint len = BIO_get_mem_data(bio, &mem);

  PyObject *res = PyString_FromStringAndSize(mem, len);
  BIO_free(bio);

  return res;
}

static PyObject *
z_policy_zorp_certificate_new_instance(PyObject * /* s */, PyObject *args)
{
  gchar *cert;
  if (!PyArg_Parse(args, "(s)", &cert))
    {
      PyErr_SetString(PyExc_ValueError, "Parameter must be a certificate in PEM format.");
      return nullptr;
    }

  BIO *bio = BIO_new_mem_buf(cert, strlen(cert));
  X509 *certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (!certificate)
    {
      PyErr_SetString(PyExc_ValueError, "Certificate must be specified as string in PEM format.");
      return nullptr;
    }

  ZPolicyDict *dict = z_policy_dict_new();
  z_policy_dict_register(dict,
                         Z_VT_METHOD,
                         "handle_extensions",
                         Z_VF_READ,
                         z_py_zorp_certificate_handle_extensions,
                         certificate,
                         X509_free);
  return z_policy_struct_new(dict, Z_PST_SHARED);
}

PyMethodDef z_policy_zorp_certificate_funcs[] =
{
  { "ZorpCertificate",  z_policy_zorp_certificate_new_instance, METH_VARARGS, NULL },
  { NULL,            NULL, 0, NULL }   /* sentinel*/
};

/**
 * z_policy_zorp_certificate_module_init
 *
 * Module initialisation - This is used only in Keybridge.py to delete extensions
 */
void
z_policy_zorp_certificate_module_init(void)
{
  Py_InitModule("Zorp.Certificate_", z_policy_zorp_certificate_funcs);
}

typedef struct _ZorpCRL
{
  PyObject_HEAD
  X509_CRL *crl;
} ZorpCRL;

static void z_py_zorp_crl_free(ZorpCRL *self);
static PyObject *z_py_zorp_crl_getattr(PyObject *o, char *name);
static PyTypeObject z_py_zorp_crl_type =
{
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "Zorp CRL",
  sizeof(ZorpCRL),
  0,
  (destructor) z_py_zorp_crl_free,
  0,                                  /* tp_print */
  z_py_zorp_crl_getattr,              /* tp_getattr */
  0,                                  /* tp_setattr */
  0,                                  /* tp_compare */
  0,                                  /* tp_repr */
  0,                                  /* tp_as_number */
  0,                                  /* tp_as_sequence */
  0,                                  /* tp_as_mapping */
  0,                                  /* tp_hash */
  0,                                  /* tp_call */
  0,                                  /* tp_str */
  0,                                  /* tp_getattro */
  0,                                  /* tp_setattro */
  0,                                  /* tp_as_buffer */
  0,                                  /* flags */
  "ZorpCRL class for Zorp",           /* docstring */
  0, 0, 0, 0,
  Z_PYTYPE_TRAILER
};


static PyObject *
z_py_zorp_crl_new(X509_CRL *crl)
{
  ZorpCRL *self;

  self = PyObject_New(ZorpCRL, &z_py_zorp_crl_type);
  self->crl = crl;
  if (!X509_CRL_up_ref(crl))
    {
      PyErr_SetString(PyExc_RuntimeError, "X509_up_ref failed.");
      return nullptr;
    }

  return (PyObject *) self;
}

static PyObject *
z_py_zorp_crl_getattr(PyObject *o, char *name)
{
  ZorpCRL *self = (ZorpCRL *) o;
  PyObject *res = NULL;
  BIO *bio;
  guint len;
  gchar *mem;
  gchar buf[512];

  if (strcmp(name, "blob") == 0)
    {
      bio = BIO_new(BIO_s_mem());

      PEM_write_bio_X509_CRL(bio, self->crl);
      len = BIO_get_mem_data(bio, &mem);
      res = PyString_FromStringAndSize(mem, len);

      BIO_free(bio);
    }
  else if (strcmp(name, "issuer") == 0)
    {
      X509_NAME_oneline(X509_CRL_get_issuer(self->crl), buf, sizeof(buf));
      res = PyString_FromString(buf);
    }
  else
    {
      PyErr_SetString(PyExc_AttributeError, "Attribute not found");
    }
  return res;
}

static void
z_py_zorp_crl_free(ZorpCRL *self)
{
  X509_CRL_free(self->crl);
  PyObject_Del(self);
}

struct ZorpCertList
{
  PyObject_HEAD
  STACK_OF(X509) *certs;
};

static Py_ssize_t z_py_zorp_cert_list_length(ZorpCertList *self);
static PyObject *z_py_zorp_cert_list_subscript(ZorpCertList *self, PyObject *ndx);
static gint z_py_zorp_cert_list_ass_subscript(ZorpCertList *self, PyObject *ndx, PyObject *new_);
static PyMappingMethods z_py_zorp_cert_list_mapping =
{
  (Z_PYMAPPING_LENFUNC_TYPE) z_py_zorp_cert_list_length,
  (binaryfunc) z_py_zorp_cert_list_subscript,
  (objobjargproc) z_py_zorp_cert_list_ass_subscript
};

static void z_py_zorp_cert_list_free(ZorpCertList *self);
static PyTypeObject z_py_zorp_cert_list_type =
{
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "Zorp Certificate List",
  sizeof(ZorpCertList),
  0,
  (destructor) z_py_zorp_cert_list_free,
  0,                                  /* tp_print */
  0,                                  /* tp_getattr */
  0,                                  /* tp_setattr */
  0,                                  /* tp_compare */
  0,                                  /* tp_repr */
  0,                                  /* tp_as_number */
  0,                                  /* tp_as_sequence */
  &z_py_zorp_cert_list_mapping,        /* tp_as_mapping */
  0,                                  /* tp_hash */
  0,                                  /* tp_call */
  0,                                  /* tp_str */
  0,                                  /* tp_getattro */
  0,                                  /* tp_setattro */
  0,                                  /* tp_as_buffer */
  0,                                  /* flags */
  "ZorpCertList class for Zorp",   /* docstring */
  0, 0, 0, 0,
  Z_PYTYPE_TRAILER
};


static PyObject *
z_py_zorp_cert_list_new(STACK_OF(X509) *certs)
{
  ZorpCertList *self;

  self = PyObject_New(ZorpCertList, &z_py_zorp_cert_list_type);
  self->certs = certs;
  return (PyObject *) self;
}

static void
z_py_zorp_cert_list_free(ZorpCertList *self)
{
  PyObject_Del(self);
}

static Py_ssize_t
z_py_zorp_cert_list_length(ZorpCertList *self)
{
  return sk_X509_num(self->certs);
}

static int
z_py_zorp_cert_list_lookup(ZorpCertList *self, PyObject *ndx)
{
  if (PyInt_Check(ndx))
    {
      /* number */

      if (PyInt_AsLong(ndx) >= 0 && PyInt_AsLong(ndx) < sk_X509_num(self->certs))
        {
          return PyInt_AsLong(ndx);
        }
    }
  else if (PyString_Check(ndx))
    {
      gchar buf[512];
      int i;

      for (i = 0; i < sk_X509_num(self->certs); i++)
        {
          X509_NAME_oneline(X509_get_subject_name(sk_X509_value(self->certs, i)), buf, sizeof(buf));
          if (strcmp(buf, PyString_AsString(ndx)) == 0)
            {
              return i;
            }
        }
    }
  return -1;
}

static PyObject *
z_py_zorp_cert_list_subscript(ZorpCertList *self, PyObject *ndx)
{
  int i;

  i = z_py_zorp_cert_list_lookup(self, ndx);
  if (i == -1)
    {
      PyErr_SetString(PyExc_KeyError, "Certificate not found.");
      return NULL;
    }
  return z_py_zorp_certificate_new(sk_X509_value(self->certs, i));
}

static gint
z_py_zorp_cert_list_ass_subscript(ZorpCertList *self, PyObject *ndx, PyObject *new_)
{
  X509 *cert = NULL;
  int i;

  if (new_)
    {
      if (PyString_Check(new_))
        {
          /* new-ban pem, berakni az i. helyere */
          cert = (X509 *)PROXY_SSL_EXTRACT_PEM(PyString_AsString(new_), PyString_Size(new_), PEM_read_bio_X509);
        }

      if (!cert)
        {
          PyErr_SetString(PyExc_TypeError, "Certificates must be specified as strings in PEM format");
          return -1;
        }
    }

  i = z_py_zorp_cert_list_lookup(self, ndx);

  if (i != -1)
    {
      X509 *p = sk_X509_delete(self->certs, i);
      X509_free(p);
   }

  if (cert)
    {
      if (X509_find_by_subject(self->certs, X509_get_subject_name(cert)))
        {
          X509_free(cert);
          PyErr_SetString(PyExc_ValueError, "Trying to add a duplicate certificate.");
          return -1;
        }

      sk_X509_push(self->certs, cert);
    }
  return 0;
}

struct ZorpCertNameList
{
  PyObject_HEAD
  STACK_OF(X509_NAME) *cert_names;
};

static Py_ssize_t z_py_zorp_cert_name_list_length(ZorpCertNameList *self);
static PyObject *z_py_zorp_cert_name_list_subscript(ZorpCertNameList *self, PyObject *ndx);
static PyMappingMethods z_py_zorp_cert_name_list_mapping =
{
  (Z_PYMAPPING_LENFUNC_TYPE) z_py_zorp_cert_name_list_length,
  (binaryfunc) z_py_zorp_cert_name_list_subscript,
  (objobjargproc) NULL
};

static void z_py_zorp_cert_name_list_free(ZorpCertNameList *self);
static PyTypeObject z_py_zorp_cert_name_list_type =
{
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "Zorp Certificate Name List",
  sizeof(ZorpCertNameList),
  0,
  (destructor) z_py_zorp_cert_name_list_free,
  0,                                  /* tp_print */
  0,                                  /* tp_getattr */
  0,                                  /* tp_setattr */
  0,                                  /* tp_compare */
  0,                                  /* tp_repr */
  0,                                  /* tp_as_number */
  0,                                  /* tp_as_sequence */
  &z_py_zorp_cert_name_list_mapping,        /* tp_as_mapping */
  0,                                  /* tp_hash */
  0,                                  /* tp_call */
  0,                                  /* tp_str */
  0,                                  /* tp_getattro */
  0,                                  /* tp_setattro */
  0,                                  /* tp_as_buffer */
  0,                                  /* flags */
  "ZorpCertNameList class for Zorp",   /* docstring */
  0, 0, 0, 0,
  Z_PYTYPE_TRAILER
};


static PyObject *
z_py_zorp_cert_name_list_new(STACK_OF(X509_NAME) *cert_names)
{
  ZorpCertNameList *self;

  self = PyObject_New(ZorpCertNameList, &z_py_zorp_cert_name_list_type);
  self->cert_names = cert_names;
  return (PyObject *) self;
}

static void
z_py_zorp_cert_name_list_free(ZorpCertNameList *self)
{
  PyObject_Del(self);
}

static Py_ssize_t
z_py_zorp_cert_name_list_length(ZorpCertNameList *self)
{
  return sk_X509_NAME_num(self->cert_names);
}

static int
z_py_zorp_cert_name_list_lookup(ZorpCertNameList *self, PyObject *ndx)
{
  if (PyInt_Check(ndx))
    {
      /* number */

      if (PyInt_AsLong(ndx) >= 0 && PyInt_AsLong(ndx) < sk_X509_NAME_num(self->cert_names))
        {
          return PyInt_AsLong(ndx);
        }
    }
  else if (PyString_Check(ndx))
    {
      gchar buf[512];
      int i, num;

      num = sk_X509_NAME_num(self->cert_names);
      for (i = 0; i < num; i++)
        {
          X509_NAME_oneline(sk_X509_NAME_value(self->cert_names, i), buf, sizeof(buf));
          if (strcmp(buf, PyString_AsString(ndx)) == 0)
            {
              return i;
            }
        }
    }
  return -1;
}

static PyObject *
z_py_zorp_cert_name_list_subscript(ZorpCertNameList *self, PyObject *ndx)
{
  gchar buf[1024];
  int i;

  i = z_py_zorp_cert_name_list_lookup(self, ndx);
  if (i == -1)
    {
      PyErr_SetString(PyExc_KeyError, "Certificate not found.");
      return NULL;
    }
  /* FIXME: return it as a string */
  X509_NAME_oneline(sk_X509_NAME_value(self->cert_names, i), buf, sizeof(buf));
  return PyString_FromString(buf);
}

struct ZorpCRLList
{
  PyObject_HEAD
  STACK_OF(X509_CRL) *crls;
};

static Py_ssize_t z_py_zorp_crl_list_length(ZorpCRLList *self);
static PyObject *z_py_zorp_crl_list_subscript(ZorpCRLList *self, PyObject *ndx);
static gint z_py_zorp_crl_list_ass_subscript(ZorpCRLList *self, PyObject *ndx, PyObject *new_);
static PyMappingMethods z_py_zorp_crl_list_mapping =
{
  (Z_PYMAPPING_LENFUNC_TYPE) z_py_zorp_crl_list_length,
  (binaryfunc) z_py_zorp_crl_list_subscript,
  (objobjargproc) z_py_zorp_crl_list_ass_subscript
};

static void z_py_zorp_crl_list_free(ZorpCRLList *self);
static PyTypeObject z_py_zorp_crl_list_type =
{
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "Zorp CRL List",
  sizeof(ZorpCRLList),
  0,
  (destructor) z_py_zorp_crl_list_free,
  0,                                  /* tp_print */
  0,                                  /* tp_getattr */
  0,                                  /* tp_setattr */
  0,                                  /* tp_compare */
  0,                                  /* tp_repr */
  0,                                  /* tp_as_number */
  0,                                  /* tp_as_sequence */
  &z_py_zorp_crl_list_mapping,        /* tp_as_mapping */
  0,                                  /* tp_hash */
  0,                                  /* tp_call */
  0,                                  /* tp_str */
  0,                                  /* tp_getattro */
  0,                                  /* tp_setattro */
  0,                                  /* tp_as_buffer */
  0,                                  /* flags */
  "ZorpCRLList class for Zorp",   /* docstring */
  0, 0, 0, 0,
  Z_PYTYPE_TRAILER
};


static PyObject *
z_py_zorp_crl_list_new(STACK_OF(X509_CRL) *crls)
{
  ZorpCRLList *self;

  self = PyObject_New(ZorpCRLList, &z_py_zorp_crl_list_type);
  self->crls = crls;
  return (PyObject *) self;
}

static void
z_py_zorp_crl_list_free(ZorpCRLList *self)
{
  PyObject_Del(self);
}

static Py_ssize_t
z_py_zorp_crl_list_length(ZorpCRLList *self)
{
  return sk_X509_CRL_num(self->crls);
}

static int
z_py_zorp_crl_list_lookup(ZorpCRLList *self, PyObject *ndx)
{
  if (PyInt_Check(ndx))
    {
      /* number */

      if (PyInt_AsLong(ndx) >= 0 && PyInt_AsLong(ndx) < sk_X509_CRL_num(self->crls))
        {
          return PyInt_AsLong(ndx);
        }
    }
  else if (PyString_Check(ndx))
    {
      gchar buf[512];
      int i;

      for (i = 0; i < sk_X509_CRL_num(self->crls); i++)
        {
          X509_NAME_oneline(X509_CRL_get_issuer(sk_X509_CRL_value(self->crls, i)), buf, sizeof(buf));
          if (strcmp(buf, PyString_AsString(ndx)) == 0)
            {
              return i;
            }
        }
    }
  return -1;
}

static PyObject *
z_py_zorp_crl_list_subscript(ZorpCRLList *self, PyObject *ndx)
{
  int i;

  i = z_py_zorp_crl_list_lookup(self, ndx);
  if (i == -1)
    {
      PyErr_SetString(PyExc_KeyError, "Certificate not found.");
      return NULL;
    }
  return z_py_zorp_crl_new(sk_X509_CRL_value(self->crls, i));
}

static gint
z_py_zorp_crl_list_ass_subscript(ZorpCRLList *self, PyObject *ndx, PyObject *new_)
{
  X509_CRL *crl = NULL;
  int i;

  if (new_)
    {
      if (PyString_Check(new_))
        {
          /* new-ban pem, berakni az i. helyere */
          crl = (X509_CRL *)PROXY_SSL_EXTRACT_PEM(PyString_AsString(new_), PyString_Size(new_), PEM_read_bio_X509_CRL);
        }

      if (!crl)
        {
          PyErr_SetString(PyExc_TypeError, "CRLs must be specified as strings in PEM format");
          return -1;
        }
    }

  i = z_py_zorp_crl_list_lookup(self, ndx);

  if (i != -1)
    {
      X509_CRL *p = sk_X509_CRL_delete(self->crls, i);
      X509_CRL_free(p);
    }

  if (crl)
    {
      sk_X509_CRL_push(self->crls, crl);
    }
  return 0;
}

ZPolicyObj *
z_py_ssl_certificate_get(ZProxy * /* self */, gchar * /* name */, gpointer value)
{
  X509 **cert = (X509 **) value;

  return z_py_zorp_certificate_new(*cert);
}

int
z_py_ssl_certificate_set(ZProxy * /* self */, gchar * /* name */, gpointer value, ZPolicyObj *new_)
{
  X509 **cert = (X509 **) value;

  if (*cert)
    {
      X509_free(*cert);
      *cert = NULL;
    }
  if (PyString_Check(new_))
    {
      (*cert) = (X509 *)PROXY_SSL_EXTRACT_PEM(PyString_AsString(new_), PyString_Size(new_), PEM_read_bio_X509);
    }
  if (!(*cert))
    {
      PyErr_SetString(PyExc_TypeError, "Certificates must be specified as strings in PEM format.");
      return -1;
    }
  return 0;
}

void
z_py_ssl_certificate_free(gpointer value)
{
  X509 **cert = (X509 **) value;

  X509_free(*cert);
}

ZPolicyObj *
z_py_ssl_privkey_get(ZProxy * /* self */, gchar * /* name */, gpointer  /* value */)
{
  return PyString_FromString("Private key retrieval is not supported.");
}

int
z_py_ssl_privkey_set(ZProxy *self, gchar * /* name */, gpointer value, ZPolicyObj *new_)
{
  EVP_PKEY **pkey = (EVP_PKEY **) value;
  GString       *passphrase;

  z_proxy_enter(self);
  if (*pkey)
    {
      EVP_PKEY_free(*pkey);
      *pkey = NULL;
    }
  if (PyString_Check(new_))
    {
      if (pkey == &self->tls_opts.local_privkey[EP_CLIENT])
        passphrase = self->tls_opts.local_privkey_passphrase[EP_CLIENT];
      else if (pkey == &self->tls_opts.local_privkey[EP_SERVER])
        passphrase = self->tls_opts.local_privkey_passphrase[EP_SERVER];
      else
        passphrase = NULL;

      /* (*pkey) = PROXY_SSL_EXTRACT_PEM(PyString_AsString(new), PyString_Size(new), PEM_read_bio_PrivateKey); */
      {
        BIO *bio = BIO_new_mem_buf(PyString_AsString(new_), PyString_Size(new_));
        (*pkey) = PEM_read_bio_PrivateKey(bio, NULL, NULL, passphrase ? passphrase->str : NULL);
        BIO_free(bio);
      }
    }
  if (!(*pkey))
    {
      PyErr_SetString(PyExc_TypeError, "Private keys must be specified as strings in PEM format.");
      z_proxy_return(self, -1);
    }
  z_proxy_return(self, 0);
}

void
z_py_ssl_privkey_free(gpointer value)
{
  EVP_PKEY **pkey = (EVP_PKEY **) value;

  EVP_PKEY_free(*pkey);
}

ZPolicyObj *
z_py_ssl_cert_name_list_get(ZProxy * /* self */, gchar * /* name */, gpointer value)
{
  STACK_OF(X509_NAME) **certnamelist = (STACK_OF(X509_NAME) **) value;

  return z_py_zorp_cert_name_list_new(*certnamelist);
}

void
z_py_ssl_cert_name_list_free(gpointer value)
{
  STACK_OF(X509_NAME) **certnamelist = (STACK_OF(X509_NAME) **) value;

  sk_X509_NAME_pop_free(*certnamelist, X509_NAME_free);
}
