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

#include <zorp/szig.h>
#include <zorpll/log.h>
#include <zorpll/io.h>
#include <zorpll/thread.h>
#include <zorpll/stream.h>
#include <zorpll/streamfd.h>
#include <zorpll/streambuf.h>
#include <zorpll/streamline.h>
#include <zorpll/sockaddr.h>
#include <zorpll/listen.h>
#include <zorp/coredump.h>
#include <zorp/policy.h>
#include <zorp/proxy.h>
#include <zorpll/process.h>

#include <string.h>
#ifdef __linux__
#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#elif defined(__FreeBSD__)
#ifdef HAVE_SYS_THR_H
#include <sys/thr.h>
#endif
#endif
#include <sys/types.h>

/*
 * The SZIG framework serves as a means to publish internal statistics. It
 * consists of three main parts:
 *   - collecting data using events
 *   - aggregate that data and represent 'results' in an N-ary tree
 *   - publish this data through a UNIX domain socket interface
 *
 * Data collection:
 *
 *   Primitive data is collected using events. An event is generated (using
 *   a simple function call) when something happens which is interesting
 *   from a statistics standpoint. For example an event is generated when a
 *   thread is started, but a similar event can be generated when a new
 *   entry becomes available in the licensed IPs hash.
 *
 * Data aggregation:
 *
 *   Aggregator functions are generic functions to be applied to events. When
 *   an event occurs all registered functions are called in the order of
 *   registration. This way several different representations of the same
 *   incoming event data are possible. For example we can register two
 *   functions to the START_THREAD event, one of them counts the current
 *   number of threads, the other counts the total number of threads started
 *   so far.
 *
 *   Each aggregator function receives a result node as argument which
 *   specifies a location where results can be stored. This result node also
 *   contains a mutex which makes it easy to synchronize acceseses to
 *   the result data.
 *
 * Data publishing:
 *
 *   A simple UNIX domain socket based interface is provided to publish
 *   the result tree.
 *
 * Node naming
 *
 *   Each node in the SZIG tree is named after its position in the tree,
 *   each level is separated by '.', special characters and '.' are escaped
 *   using the URL-like %XX form.
 *
 * Name representation
 *
 *   As the external representation of SZIG node names contain dots, these
 *   dots must be escaped within node names. An unescaped representation is
 *   used (e.g. ZSzigNode->name contains the name in raw form, without
 *   escapes), conversion between escaped/unescaped forms happens when a
 *   node is looked up.
 *
 * Locking
 *
 *   There are two parallel threads accessing the SZIG tree:
 *     1) the SZIG thread, which processes incoming events from various
 *        parts of Zorp,
 *     2) the main thread which gives access to the SZIG tree to zorpctl.
 *
 *   Two different access methods are defined: value changes, in which case
 *   values are changed in the already established tree structure, and
 *   structure changes which involves adding or removing nodes.
 *
 *   Locking tree structure changes
 *     This only happens in the SZIG thread, and races with the main thread,
 *     if the main thread is querying the same node that the SZIG thread is
 *     changing. Therefore structure changes need to be protected by a
 *     simple mutex, which is locked by the main thread lookup code and the
 *     code involving structure changes in the SZIG thread.
 *
 *   Locking value changes
 *     As it is not strictly necessary to show an exact value to zorpctl,
 *     value changes does not need to be locked, except when a complex data
 *     structure requires that (e.g. GString)
 */

static const int Z_SZIG_MAX_LINE = 131072 + 256; /* 128KiB is the max length of a single argument + a little room */
#define Z_SZIG_STATS_INTERVAL 5000      /**< interval at which samples will be taken for the average aggregator */

/**
 * ZSzigEventCallback:
 *
 * This structure describes a callback associated with a given event. It
 * stores a pointer to the function and an opaque pointer to be passed to
 * this function once it is invoked.
 **/
typedef struct _ZSzigEventCallback
{
  ZSzigNode *node;
  ZSzigEventHandler func;
  gpointer user_data;
} ZSzigEventCallback;

/**
 * ZSzigEventDesc:
 *
 * This function describes an event. Currently it contains a list of
 * callbacks to be called when the event occurs.
 **/
typedef struct _ZSzigEventDesc
{
  GList *callbacks;
} ZSzigEventDesc;

/**
 * ZSzigQueueItem:
 *
 * The asynchron queue between SZIG and the rest of Zorp contains elements
 * of this type.
 **/
typedef struct _ZSzigQueueItem
{
  ZSzigEvent event;
  ZSzigValue *param;
} ZSzigQueueItem;

/**
 * ZSzigConnection:
 *
 * Data associated with a connection accepted through the zorpctl socket.
 **/
typedef struct _ZSzigConnection
{
  guint ref_cnt;
  ZStream *stream;
} ZSzigConnection;

/* event descriptors */
static ZSzigEventDesc event_desc[Z_SZIG_MAX + 1];

/* result tree root */
static ZSzigNode *result_tree_root;
/* protects tree structure changes (adding/removing nodes, but not value changes) */
G_LOCK_DEFINE_STATIC(result_tree_structure_lock);
G_LOCK_DEFINE_STATIC(result_node_gstring_lock);
/* queue to serialize requests through */
static GAsyncQueue *szig_queue = NULL;

/* SZIG values */

/**
 * z_szig_value_repr:
 * @v: ZSzigValue instance
 * @buf: result buffer
 * @buflen: size of @buf
 *
 * This function returns the string representation of a ZSzigValue as it
 * needs to be presented to the user (e.g. zorpctl).
 **/
void
z_szig_value_repr(ZSzigValue *v, gchar *buf, gsize buflen)
{
  z_enter();
  switch (v->type)
    {
    case Z_SZIG_TYPE_NOTINIT:
      g_strlcpy(buf, "None", buflen);
      break;

    case Z_SZIG_TYPE_LONG:
      g_snprintf(buf, buflen, "%ld", v->u.long_value);
      break;

    case Z_SZIG_TYPE_TIME:
      g_snprintf(buf, buflen, "%ld:%ld", (glong) v->u.time_value.tv_sec, (glong) v->u.time_value.tv_usec);
      break;

    case Z_SZIG_TYPE_STRING:
      G_LOCK(result_node_gstring_lock);
      if (v->u.string_value)
        g_strlcpy(buf, v->u.string_value->str, buflen);
      else
        g_strlcpy(buf, "", buflen);
      G_UNLOCK(result_node_gstring_lock);
      break;

    default:
      g_assert(0);
    }
  z_return();
}

/**
 * z_szig_value_copy:
 * @target: destination ZSzigValue
 * @source: ZSzigValue to copy
 *
 * This function copies the contents of one ZSzigValue to another.
 *
 **/
void
z_szig_value_copy(ZSzigValue *target, ZSzigValue *source)
{
  z_enter();
  if (target->type != Z_SZIG_TYPE_NOTINIT)
    z_szig_value_free(target, FALSE);
  target->type = source->type;
  switch (source->type)
    {
    case Z_SZIG_TYPE_NOTINIT:
      break;

    case Z_SZIG_TYPE_LONG:
      target->u.long_value = source->u.long_value;
      break;

    case Z_SZIG_TYPE_TIME:
      memcpy(&target->u.time_value, &source->u.time_value, sizeof(source->u.time_value));
      break;

    case Z_SZIG_TYPE_STRING:
      target->u.string_value = g_string_new(source->u.string_value->str);
      break;

    default:
      /* copying this type is not supported */
      g_assert_not_reached();
    }
  z_return();
}

/**
 * z_szig_value_as_long:
 * @v: ZSzigValue instance
 *
 * This inline function asserts that v is of type Z_SZIG_TYPE_LONG, and
 * returns the associated value.
 **/
static inline glong
z_szig_value_as_long(ZSzigValue *v)
{
  g_assert(v->type == Z_SZIG_TYPE_LONG);
  return v->u.long_value;
}

/**
 * z_szig_value_as_time:
 * @v: ZSzigValue instance
 *
 * This inline function asserts that v is of type Z_SZIG_TYPE_TIME, and
 * returns the associated value.
 **/
static inline const GTimeVal *
z_szig_value_as_time(ZSzigValue *v)
{
  g_assert(v->type == Z_SZIG_TYPE_TIME);
  return &v->u.time_value;
}

/**
 * z_szig_value_as_string:
 * @v: ZSzigValue instance
 *
 * This inline function asserts that v is of type Z_SZIG_TYPE_STRING, and
 * returns the associated value.
 **/
static inline const gchar *
z_szig_value_as_string(ZSzigValue *v)
{
  g_assert(v->type == Z_SZIG_TYPE_STRING);
  return v->u.string_value->str;
}

/**
 * z_szig_value_as_gstring:
 * @v: ZSzigValue instance
 *
 * This inline function asserts that v is of type Z_SZIG_TYPE_STRING, and
 * returns the associated value as a GString pointer.
 **/
static inline GString *
z_szig_value_as_gstring(ZSzigValue *v)
{
  g_assert(v->type == Z_SZIG_TYPE_STRING);
  return v->u.string_value;
}

/**
 * z_szig_value_new_long:
 * @val: value to store as a ZSzigValue
 *
 * ZSzigValue constructor which stores a long in the newly created
 * ZSzigValue instance.
 **/
ZSzigValue *
z_szig_value_new_long(glong val)
{
  ZSzigValue *v = g_new(ZSzigValue, 1);
  v->type = Z_SZIG_TYPE_LONG;
  v->u.long_value = val;
  return v;
}

/**
 * z_szig_value_new_time:
 * @val: value to store as a ZSzigValue
 *
 * ZSzigValue constructor which stores a time in the newly created
 * ZSzigValue instance.
 **/
ZSzigValue *
z_szig_value_new_time(GTimeVal *val)
{
  ZSzigValue *v = g_new(ZSzigValue, 1);
  v->type = Z_SZIG_TYPE_TIME;
  v->u.time_value = *val;
  return v;
}

/**
 * z_szig_value_new_string:
 * @val: value to store as a ZSzigValue
 *
 * ZSzigValue constructor which stores a string in the newly created
 * ZSzigValue instance.
 **/
ZSzigValue *
z_szig_value_new_string(const gchar *val)
{
  ZSzigValue *v = g_new(ZSzigValue, 1);
  v->type = Z_SZIG_TYPE_STRING;
  v->u.string_value = g_string_new(val);
  return v;
}

/**
 * z_szig_value_add_connection_prop:
 * @v: ZSzigValue instance
 * @name: property name
 * @value: property value
 *
 * This function adds a new property to an already created ZSzigValue
 * instance.
 **/
void
z_szig_value_add_connection_prop(ZSzigValue *v, const gchar *name, const gchar *value)
{
  z_enter();
  g_assert(v->type == Z_SZIG_TYPE_CONNECTION_PROPS);

  if (v->u.service_props.string_count == Z_SZIG_MAX_PROPS)
    {
      z_log(NULL, CORE_ERROR, 0, "Internal error, error adding service property, service properties are limited to 16 elements; add_name='%s', add_value='%s'", name, value);
      z_return();
    }
  v->u.service_props.string_list[v->u.service_props.string_count * 2] = g_strdup(name);
  v->u.service_props.string_list[v->u.service_props.string_count * 2 + 1] = g_strdup(value);
  v->u.service_props.string_count++;
  z_return();
}

/**
 * z_szig_value_new_connection_props_va:
 * @service: service name
 * @instance_id: instance id (e.g. sequence number of this service)
 * @sec_conn_id: secondary connection id
 * @related_id: related connection id
 * @name: first property name
 *
 * ZSzigValue constructor which stores service parameters and associatd
 * property list in the newly created ZSzigValue instance. The list of
 * properties is passed as a va_list.
 **/
static ZSzigValue *
z_szig_value_new_connection_props_va(const gchar *service, gint instance_id, gint sec_conn_id, gushort related_id, const gchar *name, va_list l)
{
  ZSzigValue *v = g_new0(ZSzigValue, 1);

  z_enter();
  v->type = Z_SZIG_TYPE_CONNECTION_PROPS;
  v->u.service_props.name = g_strdup(service);
  v->u.service_props.instance_id = instance_id;
  v->u.service_props.sec_conn_id = sec_conn_id;
  v->u.service_props.related_id = related_id;
  while (name)
    {
      z_szig_value_add_connection_prop(v, name, va_arg(l, gchar *));
      name = va_arg(l, gchar *);
    }
  z_return(v);
}

/**
 * z_szig_value_new_connection_props:
 * @service: service name
 * @instance_id: instance id (e.g. sequence number of this service)
 * @sec_conn_id: secondary connection id
 * @related_id: related connection id
 * @name: first property name
 *
 * ZSzigValue constructor which stores service parameters and associated
 * property list in the newly created ZSzigValue instance. The
 * properties are passed as variable arguments.
 **/
ZSzigValue *
z_szig_value_new_connection_props(const gchar *service, gint instance_id, gint sec_conn_id, gushort related_id, const gchar *name, ...)
{
  ZSzigValue *v;
  va_list l;

  z_enter();
  va_start(l, name);
  v = z_szig_value_new_connection_props_va(service, instance_id, sec_conn_id, related_id, name, l);
  va_end(l);
  z_return(v);
}

/**
 * z_szig_value_add_prop:
 * @v: ZSzigValue instance
 * @name: property name
 * @value: property value
 *
 * This function adds a new property to an already created ZSzigValue
 * instance.
 **/
void
z_szig_value_add_prop(ZSzigValue *v, const gchar *name, ZSzigValue *value)
{
  z_enter();
  g_assert(v->type == Z_SZIG_TYPE_PROPS);

  if (v->u.service_props.string_count == Z_SZIG_MAX_PROPS)
    {
      z_log(NULL, CORE_ERROR, 0, "Internal error, error adding property, properties are limited to 16 elements; add_name='%s'", name);
      z_return();
    }
  v->u.props_value.name_list[v->u.props_value.value_count] = g_strdup(name);
  v->u.props_value.value_list[v->u.props_value.value_count] = value;
  v->u.props_value.value_count++;
  z_return();
}

/**
 * z_szig_value_new_props_va:
 * @service: service name
 * @name: first property name
 *
 * ZSzigValue constructor which stores service parameters and associatd
 * property list in the newly created ZSzigValue instance. The list of
 * properties is passed as a va_list.
 **/
ZSzigValue *
z_szig_value_new_props_va(const gchar *name, const gchar *first_prop, va_list l)
{
  ZSzigValue *v = g_new0(ZSzigValue, 1);
  const gchar *prop;

  z_enter();
  v->type = Z_SZIG_TYPE_PROPS;
  v->u.props_value.name = g_strdup(name);
  prop = first_prop;
  while (prop)
    {
      z_szig_value_add_prop(v, prop, va_arg(l, ZSzigValue *));
      prop = va_arg(l, gchar *);
    }
  z_return(v);
}

/**
 * z_szig_value_new_props:
 * @name: node name
 * @name: first property name
 *
 * ZSzigValue constructor which stores a named
 * property list in the newly created ZSzigValue instance. The
 * properties are passed as variable arguments.
 **/
ZSzigValue *
z_szig_value_new_props(const gchar *name, const gchar *first_prop, ...)
{
  ZSzigValue *v;
  va_list l;

  z_enter();
  va_start(l, first_prop);
  v = z_szig_value_new_props_va(name, first_prop, l);
  va_end(l);
  z_return(v);
}

/**
 * z_szig_value_free:
 * @v: ZSzigValue instance
 *
 * This function frees a ZSzigValue instance.
 **/
void
z_szig_value_free(ZSzigValue *v, gboolean free_inst)
{
  gint i;
  gint type;

  z_enter();
  if (v)
    {
      type = v->type;
      v->type = Z_SZIG_TYPE_NOTINIT;

      switch (type)
        {
        case Z_SZIG_TYPE_STRING:
          g_string_free(v->u.string_value, TRUE);
          break;

        case Z_SZIG_TYPE_CONNECTION_PROPS:
          for (i = 0; i < v->u.service_props.string_count * 2; i++)
            g_free(v->u.service_props.string_list[i]);
          g_free(v->u.service_props.name);
          break;

        case Z_SZIG_TYPE_PROPS:
          for (i = 0; i < v->u.props_value.value_count; i++)
            {
              g_free(v->u.props_value.name_list[i]);
              z_szig_value_free(v->u.props_value.value_list[i], TRUE);
            }
          g_free(v->u.props_value.name);
          break;
        }
      if (free_inst)
        g_free(v);
    }
  z_return();
}

/**
 * z_szig_node_new:
 * @name: unescaped name of the SZIG node to create
 *
 * This function creates a new z_szig_node data structure with data
 * initialized to zero and name initialized to the @name argument. A
 * ZSzigNode is a node in the SZIG tree, each has an associated name and
 * optionally an associated "data" which can be used by aggregators to store
 * their state (for example the average aggregator stores its state here)
 *
 * Returns: the newly allocated ZSzigNode structure
 **/
static ZSzigNode *
z_szig_node_new(const gchar *name)
{
  ZSzigNode *n = g_new0(ZSzigNode, 1);

  z_enter();
  n->name = g_strdup(name);
  n->children = g_ptr_array_new();
  z_return(n);
}

/**
 * z_szig_node_set_data:
 * @node: ZSzigNode instance
 * @agr_data: state needed by an aggregator
 * @notify: GDestroyNotify function to free @agr_data
 *
 * This function sets the data associated with node.
 **/
static inline void
z_szig_node_set_data(ZSzigNode *node, gpointer agr_data, GDestroyNotify notify)
{
  z_enter();
  node->agr_data = agr_data;
  node->agr_notify = notify;
  z_return();
}

/**
 * z_szig_node_get_data:
 * @node: ZSzigNode instance
 *
 * This function returns the data associated with node.
 **/
static inline gpointer
z_szig_node_get_data(ZSzigNode *node)
{
  return node->agr_data;
}

/**
 * z_szig_node_free:
 * @n: SZIG node to free
 *
 * This function frees a SZIG node from the result tree. It is currently not
 * used as nodes are never removed from the tree.
 **/
static void
z_szig_node_free(ZSzigNode *n)
{
  guint i;

  z_enter();
  if (n->name)
    g_free(n->name);
  if (n->agr_notify)
    n->agr_notify(n->agr_data);

  z_szig_value_free(&n->value, FALSE);
  for (i = 0; i < n->children->len; i++)
    z_szig_node_free((ZSzigNode *) n->children->pdata[i]);

  g_ptr_array_free(n->children, TRUE);
  g_free(n);
  z_return();
}

/**
 * z_szig_node_lookup_child:
 * @root: lookup in this node
 * @name: unescaped name to look up
 * @ndx: index where the child should have been found
 *
 * This function searches a child node by its name.
 **/
static ZSzigNode *
z_szig_node_lookup_child(ZSzigNode *root, const gchar *name, gint *ndx)
{
  gint l, h, m = 0, cmp;
  ZSzigNode *n;

  z_enter();
  if (!root)
    z_return(NULL);

  l = 0;
  h = root->children->len - 1;
  while (l <= h)
    {
      m = (l + h) >> 1;
      n = static_cast<ZSzigNode *>(g_ptr_array_index(root->children, m));
      cmp = strcmp(n->name, name);
      if (cmp > 0)
        {
          h = m - 1;
        }
      else if (cmp < 0)
        {
          l = m + 1;
        }
      else
        {
          if (ndx)
            *ndx = m;
          z_return(n);
        }
    }
  if (ndx)
    *ndx = l;
  z_return(NULL);
}

/**
 * z_szig_node_insert_child:
 * @root: insert a child to this node
 * @insert_point: insert the child at this position
 * @child: insert this child
 *
 * This function adds a child node.
 **/
static gboolean
z_szig_node_insert_child(ZSzigNode *root, gint insert_point, ZSzigNode *child)
{
  z_enter();
  if (insert_point == -1)
    {
      if (z_szig_node_lookup_child(root, child->name, &insert_point))
        z_return(FALSE); /* already present? */
    }
  g_ptr_array_set_size(root->children, root->children->len + 1);
  memmove(&root->children->pdata[insert_point+1], &root->children->pdata[insert_point], (root->children->len - insert_point - 1) * sizeof(gpointer));
  root->children->pdata[insert_point] = child;
  z_return(TRUE);
}

/**
 * z_szig_node_remove_child:
 * @root: remove a child from this node
 * @remove_point: remove the child from this position
 *
 * This function removes and frees a child node.
 **/
static void
z_szig_node_remove_child(ZSzigNode *root, gint remove_point)
{
  ZSzigNode *child;

  z_enter();
  g_assert((guint) remove_point < root->children->len);
  child = static_cast<ZSzigNode *>(root->children->pdata[remove_point]);
  memmove(&root->children->pdata[remove_point], &root->children->pdata[remove_point+1], (root->children->len - remove_point - 1) * sizeof(gpointer));
  g_ptr_array_set_size(root->children, root->children->len - 1);
  z_szig_node_free(child);
  z_return();
}

/**
 * z_szig_node_add_named_child:
 * @root: add a child to this node
 * @name: unescaped name of the new child
 *
 * This function inserts a new child node with the name specified in the
 * arguments.
 **/
static ZSzigNode *
z_szig_node_add_named_child(ZSzigNode *root, const gchar *name)
{
  gint ndx;
  ZSzigNode *child;

  z_enter();
  child = z_szig_node_lookup_child(root, name, &ndx);
  if (!child)
    {
      child = z_szig_node_new(name);
      z_szig_node_insert_child(root, ndx, child);
    }
  g_assert(child);
  z_return(child);
}

/*
 * SZIG Tree
 */

/**
 * z_szig_xdigit_value:
 * @x: hexadecimal character
 *
 * This function returns the value for a nibble.
 **/
static inline gint
z_szig_xdigit_value(guchar x)
{
  x = toupper(x);
  if (x >= '0' && x <= '9')
    return x - '0';
  else if (x >= 'A' && x <= 'F')
    return x - 'A' + 10;
  return 0;
}

/**
 * z_szig_unescape_name:
 * @name: name to remove escaping from
 * @buf: result buffer
 *
 * This function converts a name from external to internal representation by
 * resolving escaped characters.
 **/
static gchar *
z_szig_unescape_name(const gchar *name, gchar **buf)
{
  const guchar *src;
  GString *dst;

  dst = g_string_sized_new(32);
  for (src = (guchar *)name; *src; src++)
    {
      if (*src == '%')
        {
          if (isxdigit(*(src+1)) && isxdigit(*(src+2)))
            g_string_append_c(dst, (z_szig_xdigit_value(*(src+1)) << 4) | z_szig_xdigit_value(*(src+2)));
          src += 2;
        }
      else
        {
          g_string_append_c(dst, *src);
        }
    }
  *buf = dst->str;
  return g_string_free(dst, FALSE);
}

/**
 * z_szig_escape_name:
 * @name: name to add escaping to
 * @buf: result buffer
 * @buflen: size of @buf
 *
 * This function converts a name from internal to external representation by
 * escaping various characters.
 **/
static gchar *
z_szig_escape_name(const gchar *name, gchar **buf)
{
  const guchar *src;
  GString *dst;

  dst = g_string_sized_new(32);
  for (src = (guchar *)name; *src; src++)
    {
      if (*src <= 32 || *src == '.' || *src == '%' || *src > 0x7f)
        {
          g_string_append_printf(dst, "%%%02X", *src);
        }
      else
        {
          g_string_append_c(dst, *src);
        }
    }

  *buf = dst->str;
  return g_string_free(dst, FALSE);
}

/**
 * z_szig_tree_lookup:
 * @node_name: the escaped path to the variable to look up
 * @create: specifies whether an empty node should be created if the name is
 *          not found
 *
 * This function looks up or creates a node in the result tree. Names are
 * dot separated paths which specify a location in our N-ary tree. Locking
 * depends on whether we are in the SZIG or in the main thread:
 *
 *   * in the SZIG thread no locks need to be acquired to look up nodes as
 *     all possible changes are performed in the SZIG thread itself
 *   * if the @create argument is TRUE, even the SZIG thread needs to
 *     acquire result_tree_structure_lock prior to calling this function
 *   * in the main thread callers always need to acquire
 *     result_tree_structure_lock even for looking up elements
 *
 * Returns: the SZIG node if found and NULL otherwise
 **/
ZSzigNode *
z_szig_tree_lookup(const gchar *node_name, gboolean create, ZSzigNode **parent, gint *parent_ndx)
{
  gchar **split;
  ZSzigNode *root, *node = NULL;
  gint i;

  z_enter();

  if (strlen(node_name) == 0)
    {
      /* root node */
      *parent = NULL;
      *parent_ndx = -1;
      z_return(result_tree_root);
    }

  split = g_strsplit(node_name, ".", 0);
  if (!split)
    z_return(NULL);

  node = root = result_tree_root;
  for (i = 0; node && split[i]; i++)
    {
      gint insert_point = -1;
      gchar *unescaped_name;

      z_szig_unescape_name(split[i], &unescaped_name);
      node = z_szig_node_lookup_child(root, unescaped_name, &insert_point);
      if (parent)
        *parent = root;
      if (parent_ndx)
        *parent_ndx = insert_point;

      if (!node && create)
        {
          /* NOTE: tree structure changes should be locked by
           * result_tree_structure_lock, however this create
           * functionality is only used during initialization where
           * locking is not needed */

          node = z_szig_node_new(unescaped_name);
          z_szig_node_insert_child(root, insert_point, node);
        }
      g_free(unescaped_name);
      root = node;
    }
  if (!node)
    {
      if (parent)
        *parent = NULL;
      if (parent_ndx)
        *parent_ndx = -1;
    }
  g_strfreev(split);
  z_return(node);
}


/**
 * z_szig_agr_store:
 * @node: result node
 * @ev: event, not used
 * @p: event parameter, stored in destination node
 * @user_data: not used
 *
 * This aggregator function simply stores its argument in the SZIG tree.
 **/
void
z_szig_agr_store(ZSzigNode *node, ZSzigEvent  /* ev */, ZSzigValue *p, gpointer  /* user_data */)
{
  z_enter();
  z_szig_value_copy(&node->value, p);
  z_return();
}

/**
 * z_szig_agr_count_inc:
 * @node: result node
 * @ev: event, not used
 * @p: event parameter, not used
 * @user_data: not used
 *
 * This aggregator function increments the result value in a thread
 * synchronized manner.
 **/
void
z_szig_agr_count_inc(ZSzigNode *node, ZSzigEvent  /* ev */, ZSzigValue * /* p */, gpointer  /* user_data */)
{
  z_enter();
  node->value.type = Z_SZIG_TYPE_LONG;
  node->value.u.long_value++;
  z_return();
}

/**
 * z_szig_agr_count_dec:
 * @node: result node
 * @ev: event, not used
 * @p: event parameter, not used
 * @user_data: not used
 *
 * This aggregator function decrements the result value in a thread
 * synchronized manner.
 **/
void
z_szig_agr_count_dec(ZSzigNode *node, ZSzigEvent  /* ev */, ZSzigValue * /* p */, gpointer  /* user_data */)
{
  z_enter();
  node->value.type = Z_SZIG_TYPE_LONG;
  node->value.u.long_value--;
  z_return();
}

/**
 * This aggregator function stores the maximum of the values.
 *
 * @param[in, out] target_node result node
 * @param          ev event, not used
 * @param          p event parameter, not used
 * @param[in]      user_data source node name
 *
 * This aggregator function should be called for every change of the source value. It will
 * track the highest value seen over its invocations.
 *
 * @note the maximum starts from 0, so it won't work with negative values.
 **/
static void
z_szig_agr_maximum(ZSzigNode *target_node, ZSzigEvent  /* ev */, ZSzigValue * /* p */, gpointer user_data)
{
  const gchar * const source_node_name = (const gchar * const) user_data;
  ZSzigNode *source_node;
  glong current_max, value;

  z_enter();

  source_node = z_szig_tree_lookup(source_node_name, FALSE, NULL, NULL);
  if (!source_node)
    {
      /*LOG
        This message indicates an internal error, please contact your Zorp support for assistance.
       */
      z_log(NULL, CORE_ERROR, 3, "Invalid maximum aggregator, no source node; source_node='%s'", source_node_name);
      z_return();
    }

  if (target_node->value.type != Z_SZIG_TYPE_LONG)
    {
      target_node->value.type = Z_SZIG_TYPE_LONG;
      current_max = target_node->value.u.long_value = 0;
    }
  else
    current_max = z_szig_value_as_long(&target_node->value);

  value = z_szig_value_as_long(&source_node->value);

  if (value > current_max)
    {
      target_node->value.type = Z_SZIG_TYPE_LONG;
      target_node->value.u.long_value = value;
    }

  z_leave();
}

/**
 * State for the maximum aggregator function.
 **/
typedef struct _ZSzigMaxDiffState
{
  glong last_value;
  ZSzigNode *source_node;       /**< doesn't own this object */
} ZSzigMaxDiffState;

/**
 * This aggregator function stores the maximal increment seen between its invocations.
 *
 * @param[in, out] target_node result node
 * @param          ev event, not used
 * @param          p event parameter, not used
 * @param[in]      user_data source node name
 *
 * This aggregator function should be called over regular intervals. It will track the highest
 * increment of the value of the source node seen between two calls. The source node should be
 * a sequence number, e.g. incremented for each event.
 *
 * @note the maximum starts from 0, so it won't work with negative values.
 **/
void
z_szig_agr_maximum_diff(ZSzigNode *target_node, ZSzigEvent  /* ev */, ZSzigValue * /* p */, gpointer user_data)
{
  const gchar *source_node_name = (const gchar *) user_data;
  ZSzigMaxDiffState *max_state = NULL;
  glong current_value;
  glong diff = 0;

  z_enter();

  max_state = (ZSzigMaxDiffState *)z_szig_node_get_data(target_node);
  if (!max_state)       /* initialize state */
    {
      max_state = g_new0(ZSzigMaxDiffState, 1);
      max_state->source_node = z_szig_tree_lookup(source_node_name, FALSE, NULL, NULL);
      z_szig_node_set_data(target_node, max_state, g_free);
    }

  if (!max_state->source_node)
    {
      /*LOG
	This message indicates an internal error, please contact your Zorp support for assistance.
       */
      z_log(NULL, CORE_ERROR, 3, "Invalid maximum aggregator, no source node; source_node='%s'", source_node_name);
      z_return();
    }

  current_value = z_szig_value_as_long(&max_state->source_node->value);
  diff = (current_value - max_state->last_value) * 1000 / Z_SZIG_STATS_INTERVAL;
  max_state->last_value = current_value;

  if ((target_node->value.type != Z_SZIG_TYPE_LONG) || (target_node->value.u.long_value < diff))
    {
      target_node->value.type = Z_SZIG_TYPE_LONG;
      target_node->value.u.long_value = diff;
    }

  z_return();
}

/**
 * State for the average aggregator function.
 **/
typedef struct _ZSzigAvgState
{
  glong last_value;
  ZSzigNode *source_node;
  GQueue *values;       /**< values received in the last interval */
  glong sum;            /**< sum of values */
  glong interval;       /**< interval to average over, in seconds */
} ZSzigAvgState;

/**
 * Type of records to store in ZSzigAvgState::values.
 **/
typedef struct _ZSzigAvgStateValue
{
  glong value;          /**< data point */
  GTimeVal value_time;  /**< time at which it was collected */
} ZSzigAvgStateValue;

/**
 * Free the ZSzigAvgState structure, including the queue.
 *
 * @todo FIXME: check function name against naming conventions
 **/
static inline void
z_szig_agr_average_free(gpointer data)
{
  ZSzigAvgState *self = (ZSzigAvgState *)data;

  g_queue_free(self->values);
  g_free(data);
}

/**
 * Check if check_time is earlier (older) than (end_time - interval).
 *
 * @param[in] check_time time value to check
 * @param[in] end_time end of interval the beginning of which is checked
 * @param[in] interval length of interval in seconds
 *
 * @returns TRUE if check_time is earlier than the interval
 *
 * @todo FIXME: check function name against naming conventions
 **/
static inline gboolean
z_szig_agr_average_is_older(GTimeVal check_time, GTimeVal end_time, glong interval)
{
  g_time_val_add(&end_time, -interval*1000000UL);  /* was passed by value -- end_time becomes beginning_time */
  if (check_time.tv_sec < end_time.tv_sec)
    return TRUE;
  if (check_time.tv_sec > end_time.tv_sec)
    return FALSE;
  if (check_time.tv_usec < end_time.tv_usec)
    return TRUE;
  return FALSE;
}

/**
 * Aggregator function to calculate the average value for a node over a specific
 * time interval.
 *
 * @param[in, out] target_node result node
 * @param          ev event, not used
 * @param[in]      p event parameter, assumed to be a time
 * @param[in]      user_data source node name
 *
 * This aggregator function should be registered to an event with TIME
 * parameter, it calculates the average value for a node over a time interval
 * that is currently specified by the name of the node: the last numeric characters
 * of the name should be 1, 5 or 15 for 1 minute, 5 minutes and 15 minutes respectively.
 * The source node should be a sequence number, e.g. incremented for each event.
 * The increments will be averaged.
 **/
static void
z_szig_agr_average_rate(ZSzigNode *target_node, ZSzigEvent  /* ev */, ZSzigValue *p, gpointer user_data)
{
  const gchar *source_node_name = (const gchar *) user_data;
  ZSzigAvgState *avg_state;
  const GTimeVal *current_time;
  glong current_value;
  ZSzigAvgStateValue *oldest;
  ZSzigAvgStateValue *new_value;
  glong diff = 0;

  z_enter();
  target_node->value.type = Z_SZIG_TYPE_LONG;
  avg_state = (ZSzigAvgState *) z_szig_node_get_data(target_node);
  if (!avg_state)       /* initialize state */
    {
      char *last_char;

      avg_state = g_new0(ZSzigAvgState, 1);
      avg_state->values = g_queue_new();

      /* parse the interval from the node name (which ends with avg1, avg5 or avg15) */
      /** @todo FIXME: this is a really ugly solution, better find a better one. */
      last_char = strchr(target_node->name, '\0') - 1;
      if (*last_char == '1')            /* avg1 */
        {
          avg_state->interval = 1 * 60;
        }
      else if (*last_char == '5')       /* avg5 or avg15 */
        {
          last_char--;
          if (*last_char == '1')        /* avg15 */
            {
              avg_state->interval = 15 * 60;
            }
          else                          /* avg5 */
            {
              avg_state->interval = 5 * 60;
            }
        }
      else
        {
          /*LOG
            This message indicates an internal error, please contact your Zorp support for assistance.
           */
          z_log(NULL, CORE_ERROR, 3, "Failed to parse interval from node name; target_node.name='%s'", target_node->name);
            /** @todo FIXME: discuss log message format */
          g_assert_not_reached();
        }

      z_szig_node_set_data(target_node, avg_state, z_szig_agr_average_free);
    }
  if (!avg_state->source_node)
    avg_state->source_node = z_szig_tree_lookup(source_node_name, FALSE, NULL, NULL);

  if (!avg_state->source_node)
    {
      /*LOG
	This message indicates an internal error, please contact your Zorp support for assistance.
       */
      z_log(NULL, CORE_ERROR, 3, "Invalid average aggregator, no source node; source_node='%s'", source_node_name);
      z_return();
    }
  current_time = z_szig_value_as_time(p);
  current_value = z_szig_value_as_long(&avg_state->source_node->value);
  diff = current_value - avg_state->last_value;
  avg_state->last_value = current_value;

  /* while first value in the queue (peek) exists and is too old */
  oldest = static_cast<ZSzigAvgStateValue *>(g_queue_peek_head(avg_state->values));
  while (oldest && z_szig_agr_average_is_older(oldest->value_time, *current_time, avg_state->interval))
    {
      /* subtract it from sum and pop it off the queue */
      avg_state->sum -= oldest->value;
      g_free(g_queue_pop_head(avg_state->values));
      /* get the next one */
      oldest = static_cast<ZSzigAvgStateValue *>(g_queue_peek_head(avg_state->values));
    }
  /* if the queue is empty, set the sum to 0 (just to be sure) */
  if (g_queue_is_empty(avg_state->values))
    avg_state->sum = 0;
  /* put (diff, current_time) into the queue if diff isn't 0 (0-s don't need to be tracked) */
  if (diff != 0) {
      new_value = g_new0(ZSzigAvgStateValue, 1);
      new_value->value = diff;
      new_value->value_time = *current_time;
      g_queue_push_tail(avg_state->values, new_value);
      avg_state->sum += diff;
  }
  /* calculate average using sum and interval requested */
  target_node->value.type = Z_SZIG_TYPE_LONG;
  target_node->value.u.long_value = avg_state->sum / avg_state->interval;

  z_return();
}

/**
 * z_szig_agr_append_string:
 * @target_node: result node
 * @ev: event, not used
 * @p: event parameter, should be a string
 * @user_data: not used
 *
 * This aggregator function appends its parameter to the value of the target
 * node.
 **/
void
z_szig_agr_append_string(ZSzigNode *target_node, ZSzigEvent  /* ev */, ZSzigValue *p, gpointer  /* user_data */)
{
  z_enter();
  if (target_node->value.type == Z_SZIG_TYPE_NOTINIT)
    {
      target_node->value.type = Z_SZIG_TYPE_STRING;
      target_node->value.u.string_value = g_string_new(z_szig_value_as_string(p));
    }
  else
    {
      G_LOCK(result_node_gstring_lock);
      g_string_sprintfa(z_szig_value_as_gstring(&target_node->value), ":%s", z_szig_value_as_string(p));
      G_UNLOCK(result_node_gstring_lock);
    }
  z_return();
}

/**
 * Internal state to preserve between calls to z_szig_agr_per_zone_count_print_entry.
 **/
typedef struct _ZSzigAgrCountPrintState
{
  GString *printout;
  gboolean first;
} ZSzigAgrCountPrintState;

/**
 * Convert an entry in the hash table used by z_szig_agr_per_zonepair_count into a string and print it into the state.
 *
 * @param[in]      z zone which must be a char *
 * @param[in]      v value which must be a gulong
 * @param[in, out] s state which must be a ZSzigArgCountPrintState and start with an empty printout and first=TRUE
 *
 * Intended for use with g_hash_table_foreach.
 **/
static void
z_szig_agr_per_zone_count_print_entry(gpointer z, gpointer v, gpointer s)
{
  ZSzigAgrCountPrintState *state = (ZSzigAgrCountPrintState *)s;
  char *zone = (char *)z;
  gulong *value = static_cast<gulong *>(v);

  if (state->first)
    state->first = FALSE;
  else
    g_string_append(state->printout, ", ");

  g_string_append_printf(state->printout, "%s(%ld)", zone, *value);
}

/**
 * GDestroyNotify-compatible function to free a GHashTable (for when we don't want to care about reference counting it).
 *
 * @param[in] data pointer to GHashTable
 **/
static void
z_hash_table_free(gpointer data)
{
  GHashTable *hashtable = (GHashTable *)data;

  g_hash_table_destroy(hashtable);      /* free keys and values */
  g_free(data);                         /* free the table itself */
}

static void
z_szig_update_zone_count(ZSzigNode *service, const char *node_name, const char *zone_name)
{
  ZSzigNode *zones_node;
  GHashTable *hash;
  gulong *counter;
  ZSzigAgrCountPrintState print_state = { g_string_sized_new(32), TRUE };

  /* find or create stat nodes */
  zones_node = z_szig_node_add_named_child(service, node_name);
  zones_node->value.type = Z_SZIG_TYPE_STRING;

  /* get or create hash tables (state) */
  hash = (GHashTable *)z_szig_node_get_data(zones_node);
  if (!hash)
    {
      hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
      z_szig_node_set_data(zones_node, hash, z_hash_table_free);
    }

  /* lookup or create entry in hash tables */
  counter = static_cast<gulong *>(g_hash_table_lookup(hash, zone_name));
  if (!counter)
    {
      counter = g_new0(gulong, 1);
      g_hash_table_insert(hash, g_strdup(zone_name), counter);
    }

  /* increment counters */
  (*counter)++;

  /* update stats strings (node values) */
  g_hash_table_foreach(hash, z_szig_agr_per_zone_count_print_entry, &print_state);
  G_LOCK(result_node_gstring_lock);
  if (zones_node->value.u.string_value)
    g_string_free(zones_node->value.u.string_value, TRUE);
  zones_node->value.u.string_value = print_state.printout;
  G_UNLOCK(result_node_gstring_lock);

}

/**
 * Update per-zonepair connection count for the service.
 *
 * @param[in, out] service szig node of service
 * @param[in, out] related szig node of current connection
 *
 * @note refactor things done for each side into separate function(s)?
 **/
void
z_szig_agr_per_zone_count(ZSzigNode *service, ZSzigNode *related)
{
  ZSzigNode *server_zone_node;
  ZSzigNode *client_zone_node;
  char *inbound_zone_name = NULL;
  char *outbound_zone_name = NULL;

  /* check if we know both the client zone and the server zone */
  client_zone_node = z_szig_node_lookup_child(related, "client_zone", NULL);
  if (!client_zone_node)
    return;
  if (client_zone_node->value.type != Z_SZIG_TYPE_STRING)
    return;

  server_zone_node = z_szig_node_lookup_child(related, "server_zone", NULL);
  if (!server_zone_node)
    return;
  if (server_zone_node->value.type != Z_SZIG_TYPE_STRING)
    return;

  /* get keys for the hash tables */
  inbound_zone_name = server_zone_node->value.u.string_value->str;
  outbound_zone_name = client_zone_node->value.u.string_value->str;

  z_szig_update_zone_count(service, "inbound_zones", inbound_zone_name);
  z_szig_update_zone_count(service, "outbound_zones", outbound_zone_name);

}

static void
z_szig_add_zone_cnt(ZSzigServiceProps *props, ZSzigNode *related)
{
  gchar *escaped_name = z_szig_escape_name(props->name, &escaped_name);
  const auto node_name = std::string("service.") + escaped_name;
  g_free(escaped_name);

  ZSzigNode *parent;
  gint parent_ndx;
  ZSzigNode *service = z_szig_tree_lookup(node_name.c_str(), TRUE, &parent, &parent_ndx);

  /* called here so that up-to-date data is already available in the tree */
  if (service != NULL)
    z_szig_agr_per_zone_count(service, related);
}
/**
 * z_szig_agr_flat_connection_props:
 * @target_node: result node
 * @ev: event, not used
 * @p: event parameter, should be a service_props value
 * @user_data: not used
 *
 * This aggregator function lays out a service property parameter as nodes
 * under target_node. It is used to represent service information.
 **/
void
z_szig_agr_flat_connection_props(ZSzigNode *target_node, ZSzigEvent  /* ev */, ZSzigValue *p, gpointer  /* user_data */)
{
  ZSzigServiceProps *props;
  ZSzigNode *service, *instance, *sec_conn, *related, *node;
  gchar buf[128];
  gint i;

  z_enter();
  g_return_if_fail(p->type == Z_SZIG_TYPE_CONNECTION_PROPS);
  props = &p->u.service_props;

  /* create service node */
  G_LOCK(result_tree_structure_lock);
  service = z_szig_node_add_named_child(target_node, props->name);
  g_snprintf(buf, sizeof(buf), "%d", props->instance_id);
  instance = z_szig_node_add_named_child(service, buf);
  g_snprintf(buf, sizeof(buf), "%d", props->sec_conn_id);
  sec_conn = z_szig_node_add_named_child(instance, buf);
  g_snprintf(buf, sizeof(buf), "%d", props->related_id);
  related = z_szig_node_add_named_child(sec_conn, buf);

  for (i = 0; i < props->string_count; i++)
    {
      node = z_szig_node_add_named_child(related, props->string_list[i * 2]);
      if (node->value.type != Z_SZIG_TYPE_NOTINIT)
        z_szig_value_free(&node->value, FALSE);

      node->value.type = Z_SZIG_TYPE_STRING;
      node->value.u.string_value = g_string_new(props->string_list[i * 2 + 1]);
      if (strcmp(node->name, "server_zone") == 0)
        {
          z_szig_add_zone_cnt(props, related);
        }
    }
  G_UNLOCK(result_tree_structure_lock);

  z_return();
}

/**
 * z_szig_agr_del_connection_props:
 * @target_node: result node
 * @ev: event, not used
 * @p: event parameter, should be a service_props value
 * @user_data: not used
 *
 * This aggregator function removes the service specific children from
 * target_node.
 **/
void
z_szig_agr_del_connection_props(ZSzigNode *target_node, ZSzigEvent  /* ev */, ZSzigValue *p, gpointer  /* user_data */)
{
  ZSzigServiceProps *props;
  ZSzigNode *service, *instance, *secondary;
  gchar buf[16];
  gint instance_ndx, secondary_ndx;

  z_enter();
  g_return_if_fail(p->type == Z_SZIG_TYPE_CONNECTION_PROPS);
  props = &p->u.service_props;
  service = z_szig_node_lookup_child(target_node, props->name, NULL);
  g_snprintf(buf, sizeof(buf), "%d", props->instance_id);
  instance = z_szig_node_lookup_child(service, buf, &instance_ndx);
  g_snprintf(buf, sizeof(buf), "%d", props->sec_conn_id);
  secondary = z_szig_node_lookup_child(instance, buf, &secondary_ndx);

  if (!secondary)
    {
      z_log(NULL, CORE_ERROR, 0, "Internal error, end-of-service notification referred to a non-existent service; service='%s:%d:%d'", props->name, props->instance_id, props->sec_conn_id);
      z_return();
    }

  G_LOCK(result_tree_structure_lock);
  z_szig_node_remove_child(instance, secondary_ndx);

  if (!instance->children->len)
    z_szig_node_remove_child(service, instance_ndx);

  G_UNLOCK(result_tree_structure_lock);
  z_return();
}

/**
 * z_szig_agr_flat_props:
 * @target_node: result node
 * @ev: event, not used
 * @p: event parameter, should be a service_props value
 * @user_data: not used
 *
 * This aggregator function lays out a property list parameter as nodes
 * under target_node. It is used to represent a generic subtree of information.
 *
 * FIXME: this function should support recursive Z_SZIG_TYPE_PROPS
 * structures and flat those out as a recursive tree structure, but it
 * assumes that any Z_SZIG_TYPE_PROPS value has only a single level of
 * children. But this is enough for current uses (e.g. RELOAD)
 **/
void
z_szig_agr_flat_props(ZSzigNode *target_node, ZSzigEvent  /* ev */, ZSzigValue *p, gpointer  /* user_data */)
{
  ZSzigProps *props;
  ZSzigNode *root, *node;
  gint i;

  z_enter();
  g_return_if_fail(p->type == Z_SZIG_TYPE_PROPS);
  props = &p->u.props_value;

  /* create service node */
  G_LOCK(result_tree_structure_lock);
  root = z_szig_node_add_named_child(target_node, props->name);
  for (i = 0; i < props->value_count; i++)
    {
      node = z_szig_node_add_named_child(root, props->name_list[i]);
      z_szig_value_copy(&node->value, props->value_list[i]);
    }
  G_UNLOCK(result_tree_structure_lock);
  z_return();
}

/**
 * This function aggregates the results of z_szig_agr_maximum_diff for all services.
 **/
void
z_szig_agr_service_maximum_diff(ZSzigNode *target_node, ZSzigEvent ev, ZSzigValue *p, gpointer user_data)
{
  guint i;
  z_enter();

  for (i = 0; i < target_node->children->len; i++)
    {
      ZSzigNode *current_node = (ZSzigNode *) target_node->children->pdata[i];
      ZSzigNode *max_node;
      gchar *escaped_name = NULL;
      gchar *max_nodename;
      gchar *src_nodename;

      escaped_name = z_szig_escape_name(current_node->name, &escaped_name);
      max_nodename = g_strconcat("service.", escaped_name, ".", (gchar *)user_data, NULL);
      src_nodename = g_strconcat("service.", escaped_name, ".session_number", NULL);
      g_free(escaped_name);

      max_node = z_szig_tree_lookup(max_nodename, TRUE, NULL, NULL);
      z_szig_agr_maximum_diff(max_node, ev, p, (gpointer)src_nodename);

      g_free(src_nodename);
      g_free(max_nodename);
    }
  z_return();
}

void
z_szig_agr_service_average_rate(ZSzigNode *target_node, ZSzigEvent ev, ZSzigValue *p, gpointer user_data)
{
  guint i;
  z_enter();

  for (i = 0; i < target_node->children->len; i++)
    {
      ZSzigNode *current_node = (ZSzigNode *) target_node->children->pdata[i];
      ZSzigNode *avg_node;
      gchar *avg_nodename;
      gchar *src_nodename;
      gchar *escaped_name = NULL;

      escaped_name = z_szig_escape_name(current_node->name, &escaped_name);
      avg_nodename = g_strconcat("service.", escaped_name, ".", (gchar *)user_data, NULL);
      src_nodename = g_strconcat("service.", escaped_name, ".session_number", NULL);
      g_free(escaped_name);

      avg_node = z_szig_tree_lookup(avg_nodename, TRUE, NULL, NULL);
      z_szig_agr_average_rate(avg_node, ev, p, (gpointer)src_nodename);

      g_free(src_nodename);
      g_free(avg_nodename);
    }
  z_return();
}

static void
z_szig_agr_service_maximum(ZSzigNode *target_node, ZSzigEvent ev, ZSzigValue *p, gpointer  /* user_data */)
{
  guint i;

  z_enter();

  for (i = 0; i < target_node->children->len; i++)
    {
      const ZSzigNode * const current_node = (const ZSzigNode * const) target_node->children->pdata[i];
      ZSzigNode *avg_node;
      gchar *avg_nodename;
      gchar *src_nodename;
      gchar *escaped_name = NULL;

      escaped_name = z_szig_escape_name(current_node->name, &escaped_name);
      avg_nodename = g_strconcat("service.", escaped_name, ".sessions_max", NULL);
      src_nodename = g_strconcat("service.", escaped_name, ".sessions_running", NULL);
      g_free(escaped_name);

      avg_node = z_szig_tree_lookup(avg_nodename, TRUE, NULL, NULL);
      z_szig_agr_maximum(avg_node, ev, p, (gpointer)src_nodename);
      g_free(src_nodename);
      g_free(avg_nodename);
    }

  z_leave();
}

/* general framework */

/**
 * z_szig_event_get_desc:
 * @ev: event type
 *
 * This function returns the event descriptor for the event @ev.
 **/
static inline ZSzigEventDesc *
z_szig_event_get_desc(ZSzigEvent ev)
{
  g_assert(ev >= 0 && ev <= Z_SZIG_MAX);
  return &event_desc[ev];
}

/**
 * z_szig_process_event:
 * @ev: szig event (Z_SZIG_*)
 * @param: a ZSzigValue parameter for event
 *
 * Main SZIG entry point used by various parts of Zorp to inform SZIG about
 * an interesting event. It can be called from all threads, information is
 * sent through a GAsyncQueue.
 **/
void
z_szig_event(ZSzigEvent ev, ZSzigValue *param)
{
  ZSzigQueueItem *q = g_new(ZSzigQueueItem, 1);

  z_enter();
  q->event = ev;
  q->param = param;
  if (szig_queue)
    {
      static gint warn_counter = 1;

      z_trace(NULL, "Sending szig event; object='%p'", q);
      if (g_async_queue_length(szig_queue) > 1000 * warn_counter)
        {
          z_log(NULL, CORE_ERROR, 1, "Internal error, SZIG queue overflow;");
          warn_counter++;
        }
      g_async_queue_push(szig_queue, q);
    }
  z_return();
}

/**
 * z_szig_process_event:
 * @ev: szig event to handle
 * @param: szig event handle
 *
 * This function is called from the SZIG thread to process queued events.
 **/
void
z_szig_process_event(ZSzigEvent ev, ZSzigValue *param)
{
  ZSzigEventDesc *d;
  ZSzigEventCallback *cb;
  GList *p;

  z_enter();
  d = z_szig_event_get_desc(ev);
  for (p = d->callbacks; p; p = g_list_next(p))
    {
      cb = (ZSzigEventCallback *) p->data;
      cb->func(cb->node, ev, param, cb->user_data);
    }

  z_szig_value_free(param, TRUE);
  z_return();
}

/**
 * z_szig_register_handler:
 * @ev: szig event
 * @func: event handler function
 * @node_name: target node name, where the aggregator stores calculated information
 * @user_data: pointer passed to @func
 *
 * This function registers an aggregator for the specified event using the
 * specified target node.
 **/
static void
z_szig_register_handler(ZSzigEvent ev, ZSzigEventHandler func, const gchar *node_name, gconstpointer user_data)
{
  ZSzigEventCallback *cb;
  ZSzigEventDesc *d;

  d = z_szig_event_get_desc(ev);

  cb = g_new0(ZSzigEventCallback, 1);
  cb->node = z_szig_tree_lookup(node_name, TRUE, NULL, NULL);
  cb->user_data = const_cast<gpointer>(user_data);
  cb->func = func;
  d->callbacks = g_list_append(d->callbacks, cb);
}

/* basic SZIG events */

/**
 * z_szig_thread_started:
 * @self: ZThread instance, not used
 * @user_data: not used
 *
 * This function is registered as a thread startup function. It simply generates a
 * Z_SZIG_THREAD_START event.
 **/
static void
z_szig_thread_started(ZThread * /* self */, gpointer  /* user_data */)
{
  z_szig_event(Z_SZIG_THREAD_START, NULL);
}

/**
 * z_szig_thread_stopped:
 * @self: ZThread instance, not used
 * @user_data: not used
 *
 * This function is registered as a thread stop function. It simply generates a
 * Z_SZIG_THREAD_STOP event.
 **/
static void
z_szig_thread_stopped(ZThread * /* self */, gpointer  /* user_data */)
{
  z_szig_event(Z_SZIG_THREAD_STOP, NULL);
}

/**
 * This function is called every Z_SZIG_STATS_INTERVAL milliseconds to generate a SZIG event.
 *
 * @param[in] source GSource instance
 **/
static gboolean
z_szig_tick_callback(GSource * /* source */)
{
  GTimeVal current_time;
  static guint ticks = 0;

  g_get_current_time(&current_time);
  z_szig_event(Z_SZIG_TICK, z_szig_value_new_time(&current_time));

  ticks++;
  return TRUE;
}

/**
 * z_szig_thread:
 * @st: thread parameter, not used
 *
 * This is the SZIG thread main function, it basically waits for and
 * processes SZIG events sent by z_szig_event().
 **/
static gpointer
z_szig_thread(gpointer  /* st */)
{
  if (!szig_queue)
    return NULL;
  while (1)
    {
      ZSzigQueueItem *q = (ZSzigQueueItem *) g_async_queue_pop(szig_queue);

      z_trace(NULL, "Received szig event; object='%p'", q);
      z_szig_process_event(q->event, q->param);
      g_free(q);
    }
  return NULL;
}

/* SZIG I/O */

/**
 * z_szig_connection_unref:
 * @self: ZSzigConnection instance
 *
 * This function decrements the reference count for @self and frees it if it
 * reaches 0.
 **/
static void
z_szig_connection_unref(ZSzigConnection *self)
{
  if (z_decref(&self->ref_cnt) == 0)
    {
      g_free(self);
    }
}

static void
z_szig_node_print_full_name(gchar *buf, size_t buflen, gchar *prefix, ZSzigNode *node)
{
  gchar *escaped_name = NULL;

  if (prefix && strlen(prefix) > 0)
    g_snprintf(buf, buflen, "%s.%s\n", prefix, z_szig_escape_name(node->name, &escaped_name));
  else
    g_snprintf(buf, buflen, "%s\n", z_szig_escape_name(node->name, &escaped_name));

  if (escaped_name != NULL)
    g_free(escaped_name);
}

/**
 * z_szig_handle_command:
 * @conn: ZSzigConnection instance
 * @cmd_line: command to run
 *
 * This is the main processing function for the SZIG command channel. It
 * runs in the main thread whenever an incoming line is detected by the poll
 * loop.
 **/
static gboolean
z_szig_handle_command(ZSzigConnection *conn, gchar *cmd_line)
{
  gchar response[16384], *cmd, *name;
  gint node_ndx;
  ZSzigNode *node, *node_parent = NULL;
  gchar **argv;
  const gchar *logspec;
  gint direction, value;
  gboolean new_state;

  z_enter();
  argv = g_strsplit(cmd_line, " ", 0);
  if (!argv || !argv[0])
    {
      if (argv)
        g_strfreev(argv);
      z_return(FALSE);
    }

  cmd = argv[0];
  g_strlcpy(response, "None\n", sizeof(response));
  if (strcmp(cmd, "GETVALUE") == 0 ||
      strcmp(cmd, "GETCHILD") == 0 ||
      strcmp(cmd, "GETSBLNG") == 0)
    {
      name = argv[1];
      G_LOCK(result_tree_structure_lock);
      node = z_szig_tree_lookup(name, FALSE, &node_parent, &node_ndx);
      if (strcmp(cmd, "GETVALUE") == 0)
        {
          if (node)
            {
              z_szig_value_repr(&node->value, response, sizeof(response) - 1);
              strncat(response, "\n", sizeof(response) - strlen(response) - 1);
            }
        }
      else if (strcmp(cmd, "GETCHILD") == 0)
        {
          if (node && node->children->len)
            {
              node = (ZSzigNode *) node->children->pdata[0];

              z_szig_node_print_full_name(response, sizeof(response), name, node);
            }
        }
      else if (strcmp(cmd, "GETSBLNG") == 0)
        {
          if (node && node_parent && (gint) (node_parent->children->len - 1) > node_ndx)
            {
              gchar *e = name + strlen(name) - 1;

              node = (ZSzigNode *) node_parent->children->pdata[node_ndx+1];
              while (e > name && *e != '.')
                e--;
              *e = 0;

              z_szig_node_print_full_name(response, sizeof(response), name, node);
            }
        }
      G_UNLOCK(result_tree_structure_lock);
    }
  else if (strcmp(cmd, "LOGGING") == 0)
    {
      g_strlcpy(response, "FAIL\n", sizeof(response));
      if (!argv[1])
        g_strlcpy(response, "FAIL LOGGING subcommand required", sizeof(response));
      else if (strcmp(argv[1], "VINC") == 0 ||
               strcmp(argv[1], "VDEC") == 0 ||
               strcmp(argv[1], "VSET") == 0)
        {
          if (argv[1][1] == 'I')
            direction = 1;
          else if (argv[1][1] == 'D')
            direction = -1;
          else
            direction = 0;

          if (argv[2])
            value = strtol(argv[2], NULL, 10);
          else
            value = 0;

          if (z_log_change_verbose_level(direction, value, &value))
            {
              g_snprintf(response, sizeof(response), "OK %d\n", value);
            }
          else
            g_snprintf(response, sizeof(response), "FAIL Error changing verbose level\n");
        }
      else if (strcmp(argv[1], "VGET") == 0)
        {
          if (z_log_change_verbose_level(1, 0, &value))
            g_snprintf(response, sizeof(response), "OK %d\n", value);
          else
            g_snprintf(response, sizeof(response), "FAIL Error querying verbose level\n");

        }
      else if (strcmp(argv[1], "GETSPEC") == 0)
        {
          if (z_log_change_logspec(NULL, &logspec))
            g_snprintf(response, sizeof(response), "OK %s\n", logspec ? logspec : "");
          else
            g_snprintf(response, sizeof(response), "FAIL Error querying logspec\n");
        }
      else if (strcmp(argv[1], "SETSPEC") == 0)
        {
          if (argv[2])
            {
              if (z_log_change_logspec(argv[2], &logspec))
                {
                  g_snprintf(response, sizeof(response), "OK %s\n", logspec);
                }
              else
                g_snprintf(response, sizeof(response), "FAIL Error setting logspec\n");
            }
          else
            {
              g_snprintf(response, sizeof(response), "FAIL No logspec specified\n");
            }
        }
    }
  else if (strcmp(cmd, "DEADLOCKCHECK") == 0)
    {
      g_strlcpy(response, "FAIL\n", sizeof(response));
      if (!argv[1])
        g_strlcpy(response, "FAIL DEADLOCKCHECK subcommand required", sizeof(response));
      else if (strcmp(argv[1], "ENABLE") == 0 ||
               strcmp(argv[1], "DISABLE") == 0)
        {
          if (argv[1][0] == 'E')
            new_state = TRUE;
          else
            new_state = FALSE;

          z_process_set_check_enable(new_state);
          g_snprintf(response, sizeof(response), "OK\n");
        }
      else if (strcmp(argv[1], "GET") == 0)
        {
          g_snprintf(response, sizeof(response), "OK %d\n", z_process_get_check_enable() ? 1 : 0);
        }
    }
  else if (strcmp(cmd, "RELOAD") == 0)
    {
      if (!argv[1])
        {
          z_main_loop_initiate_reload(FALSE);
          g_strlcpy(response, "OK Reload initiated", sizeof(response));
        }
      else if (strcmp(argv[1], "RESULT") == 0)
        {
          if (z_main_loop_get_last_reload_result())
            g_strlcpy(response, "OK Reload successful", sizeof(response));
          else
            g_strlcpy(response, "FAIL Reload failed", sizeof(response));
        }
      else
        {
          g_strlcpy(response, "FAIL Unknown RELOAD subcommand", sizeof(response));
        }
    }
  else if (strcmp(cmd, "COREDUMP") == 0)
    {
      if (z_coredump_create() < 0)
        g_strlcpy(response, "FAIL Dumping core failed", sizeof(response));
      else
        g_strlcpy(response, "OK Core dump created", sizeof(response));
    }
  else
    {
      g_strlcpy(response, "FAIL No such command", sizeof(response));
    }

  g_strfreev(argv);
  if (z_stream_write_buf(conn->stream, response, strlen(response), TRUE, FALSE) != G_IO_STATUS_NORMAL)
    z_return(FALSE);

  z_return(TRUE);
}

/**
 * z_szig_read_callback:
 * @stream: ZStream instance
 * @cond: condition that triggered this callback
 * @user_data: ZSzigConnection passed as user_data
 *
 * This function is invoked whenever a complete line is available from the
 * zorpctl client. It basically reads the line and runs the command using
 * z_szig_handle_command().
 **/
static gboolean
z_szig_read_callback(ZStream *stream, GIOCondition  /* cond */, gpointer user_data)
{
  ZSzigConnection *conn = (ZSzigConnection *) user_data;
  gchar *buf;
  gsize buflen = Z_SZIG_MAX_LINE - 1;
  GIOStatus res;
  ZStream *tmp_stream;

  z_enter();
  buf = static_cast<gchar *>(malloc(Z_SZIG_MAX_LINE));
  res = z_stream_line_get_copy(stream, buf, &buflen, NULL);
  if (res == G_IO_STATUS_NORMAL)
    {
      buf[buflen] = 0;
      if (z_szig_handle_command(conn, buf))
        {
          g_free(buf);
          z_return(TRUE);
        }
    }
  else if (res == G_IO_STATUS_AGAIN)
    {
      g_free(buf);
      z_return(TRUE);
    }

  z_stream_close(stream, NULL);
  tmp_stream = conn->stream;
  conn->stream = NULL;
  z_stream_unref(tmp_stream);
  g_free(buf);
  z_return(FALSE);
}

/**
 * z_szig_accept_callback:
 * @fd: fd that refers to the connection
 * @client: socket address
 * @last_connection: this is the last connection (when accept_one was specified)
 * @user_data: opaque pointer
 *
 * This function is called as soon as a new connection is received, it
 * basically creates a new ZSzigConnection and registers the stream with the
 * main loop.
 **/
static gboolean
z_szig_accept_callback(ZStream *fdstream,
                       ZSockAddr *client,
                       ZSockAddr *dest,
                       gpointer   /* user_data */)
{
  ZSzigConnection *conn;
  ZStream *linestream, *bufstream;
  gchar buf[32];
  static gint szig_conn_id = 0;

  g_snprintf(buf, sizeof(buf), "szig/conn:%d/stream", szig_conn_id);
  szig_conn_id++;
  z_stream_set_name(fdstream, buf);
  z_stream_set_nonblock(fdstream, TRUE);
  linestream = z_stream_line_new(fdstream, Z_SZIG_MAX_LINE, ZRL_EOL_NL);
  bufstream = z_stream_buf_new(linestream, 1024, 2048);

  z_stream_unref(fdstream);
  z_stream_unref(linestream);

  conn = g_new0(ZSzigConnection, 1);
  conn->ref_cnt = 1;
  conn->stream = bufstream;

  z_stream_set_callback(conn->stream, G_IO_IN, z_szig_read_callback, conn, (GDestroyNotify) z_szig_connection_unref);
  z_stream_set_cond(conn->stream, G_IO_IN, TRUE);

  z_stream_attach_source(conn->stream, g_main_context_default());
  z_sockaddr_unref(client);
  z_sockaddr_unref(dest);
  return TRUE;
}

/**
 * z_szig_init:
 * @instance_name: the virtual name of this Zorp instance
 *
 * This function initializes the SZIG subsystem, creates the UNIX domain
 * socket and initializes basic aggregations.
 **/
void
z_szig_init(const gchar *instance_name)
{
  ZSockAddr *sockaddr;
  ZListener *listen;
  gchar buf[256];
  GSource *tick_source;

  result_tree_root = z_szig_node_new(instance_name);
  memset(event_desc, 0, sizeof(event_desc));
  szig_queue = g_async_queue_new();

  z_szig_register_handler(Z_SZIG_CONNECTION_START, z_szig_agr_count_inc, "stats.sessions_running", NULL);
  z_szig_register_handler(Z_SZIG_CONNECTION_STOP, z_szig_agr_count_dec, "stats.sessions_running", NULL);

  z_szig_register_handler(Z_SZIG_THREAD_START, z_szig_agr_count_inc, "stats.threads_running", NULL);
  z_szig_register_handler(Z_SZIG_THREAD_STOP,  z_szig_agr_count_dec, "stats.threads_running", NULL);
  z_szig_register_handler(Z_SZIG_THREAD_START, z_szig_agr_count_inc, "stats.thread_number", NULL);
  z_szig_register_handler(Z_SZIG_THREAD_START, z_szig_agr_maximum, "stats.threads_max", "stats.threads_running");

  z_szig_register_handler(Z_SZIG_TICK, z_szig_agr_average_rate, "stats.thread_rate_avg1", "stats.thread_number");
  z_szig_register_handler(Z_SZIG_TICK, z_szig_agr_average_rate, "stats.thread_rate_avg5", "stats.thread_number");
  z_szig_register_handler(Z_SZIG_TICK, z_szig_agr_average_rate, "stats.thread_rate_avg15", "stats.thread_number");
  z_szig_register_handler(Z_SZIG_TICK, z_szig_agr_maximum_diff, "stats.thread_rate_max", "stats.thread_number");
  z_szig_register_handler(Z_SZIG_CONNECTION_PROPS, z_szig_agr_flat_connection_props, "conns", NULL);
  z_szig_register_handler(Z_SZIG_CONNECTION_STOP, z_szig_agr_del_connection_props, "conns", NULL);

  z_szig_register_handler(Z_SZIG_SERVICE_COUNT, z_szig_agr_flat_props, "service", NULL);
  z_szig_register_handler(Z_SZIG_SERVICE_COUNT, z_szig_agr_service_maximum, "service", NULL);
  z_szig_register_handler(Z_SZIG_TICK, z_szig_agr_service_average_rate, "service", "rate_avg1");
  z_szig_register_handler(Z_SZIG_TICK, z_szig_agr_service_average_rate, "service", "rate_avg5");
  z_szig_register_handler(Z_SZIG_TICK, z_szig_agr_service_average_rate, "service", "rate_avg15");
  z_szig_register_handler(Z_SZIG_TICK, z_szig_agr_service_maximum_diff, "service", "rate_max");

  z_szig_register_handler(Z_SZIG_AUDIT_START, z_szig_agr_count_inc, "stats.audit_running", NULL);
  z_szig_register_handler(Z_SZIG_AUDIT_STOP,  z_szig_agr_count_dec, "stats.audit_running", NULL);
  z_szig_register_handler(Z_SZIG_AUDIT_START, z_szig_agr_count_inc, "stats.audit_number", NULL);

  z_szig_register_handler(Z_SZIG_RELOAD, z_szig_agr_flat_props, "info", NULL);


  /* we need an offset of 2 to count the number of threads that were started before SZIG init */
  z_szig_thread_started(NULL, NULL);
  z_szig_thread_started(NULL, NULL);

  z_thread_register_start_callback((GFunc) z_szig_thread_started, NULL);
  z_thread_register_stop_callback((GFunc) z_szig_thread_stopped, NULL);
  tick_source = g_timeout_source_new(Z_SZIG_STATS_INTERVAL);
  g_source_set_callback(tick_source, (GSourceFunc) z_szig_tick_callback, tick_source, NULL);
  g_source_attach(tick_source, g_main_context_default());

  g_snprintf(buf, sizeof(buf), "%s.%s", ZORP_SZIG_SOCKET_NAME, instance_name);

  sockaddr = z_sockaddr_unix_new(buf);

  listen = z_stream_listener_new("szig/listen", sockaddr, FALSE, 255, z_szig_accept_callback, NULL);
  if (listen)
    {
      if (!z_listener_start(listen))
        {
          /*LOG
            This message reports that the SZIG framework was unable to create
            its socket and thus zorpctl won't be able to access and display
            internal Zorp information.
           */
          z_log(NULL, CORE_INFO, 4, "Failed to create SZIG socket; name='%s'", buf);
        }
      z_listener_unref(listen);
    }
  z_sockaddr_unref(sockaddr);

  z_thread_new("szig/thread", z_szig_thread, NULL);
}

void
z_szig_destroy(void)
{
  /* FIXME: free result tree */
}

static int
get_thread_id(void)
{
    int ret = -1;

#ifdef __linux__
    ret = syscall(SYS_gettid);
#elif defined(__NetBSD__)
    ret = _lwp_self();
#elif defined(__FreeBSD__)
    long lwpid;
    thr_self(&lwpid);
    ret = lwpid;
#endif

    return ret;
}

void
z_szig_value_add_thread_id(ZProxy *proxy)
{
  PyObject *container;
  PyObject *service_name_value;
  PyObject *instance_id_value;
  gchar *service_name = NULL;
  gint instance_id;
  gboolean vars_parsed;

  z_policy_thread_acquire(proxy->thread);
  container = (PyObject *) proxy->handler;

  service_name_value = z_policy_getattr_expr(container, "session.owner.service.name");
  instance_id_value = z_policy_getattr_expr(container, "session.owner.instance_id");

  vars_parsed = z_policy_var_parse_str(service_name_value, &service_name) &&
                z_policy_var_parse_int(instance_id_value, &instance_id);

  if (vars_parsed)
    {
      pid_t tid;
      ZSzigValue *sv;
      gchar *tid_str;

      tid = (pid_t) get_thread_id();
      tid_str = g_strdup_printf("%d", tid);
      sv = z_szig_value_new_connection_props(service_name, instance_id, 0, 0, NULL);
      z_szig_value_add_connection_prop(sv, "thread_id", tid_str);
      z_szig_event(Z_SZIG_CONNECTION_PROPS, sv);
      g_free(tid_str);
    }

  g_free(service_name);
  z_policy_thread_release(proxy->thread);
}
