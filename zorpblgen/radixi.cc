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

#include "radixi.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

static void
ri_add_value(RINode *node, RIValue value)
{
  if (node->num_values < MAX_VALUES)
    node->values[node->num_values++] = value;
}

gint
ri_node_cmp(const void *ap, const void *bp)
{
  RINode *a = *(RINode * const *) ap;
  RINode *b = *(RINode * const *) bp;

  if (a->key[0] < b->key[0])
    return -1;
  else if (a->key[0] > b->key[0])
    return 1;
  return 0;
}

static void
ri_add_child(RINode *parent, RINode *child)
{
  parent->children = static_cast<RINode **>(g_realloc(parent->children, (sizeof(RINode *) * (parent->num_children + 1))));

  //FIXME: we could do a simple sorted insert without resorting always
  parent->children[(parent->num_children)++] = child;

  qsort(&(parent->children[0]), parent->num_children, sizeof(RINode *), ri_node_cmp);
}

static RINode *
ri_find_child(RINode *root, gchar key)
{
  guint l, u, idx;
  gchar k = key;

  l = 0;
  u = root->num_children;

  while (l < u)
    {
      idx = (l + u) / 2;

      if (root->children[idx]->key[0] > k)
        u = idx;
      else if (root->children[idx]->key[0] < k)
        l = idx + 1;
      else
        return root->children[idx];
    }

  return NULL;
}

guint
ri_insert_node(RINode *root, const gchar *key, guint keylen, RIValue value)
{
  RINode *node;
  guint nodelen = root->keylen;
  guint ret = 0;
  guint m, i = 0;

  if (nodelen < 2)
    i = nodelen;
  else
    {
      m = MIN(keylen, nodelen);

      i = 1;

      while (i < m)
        {
          if (key[i] != root->key[i])
            break;

          i++;
        }
    }

  if (i == 0 || (i < keylen && i >= nodelen))
    {
      /*either at the root or we need to go down the tree on the right child */

      node = ri_find_child(root, key[i]);

      if (node)
        {
          ret = ri_insert_node(node, key + i, keylen - i, value);
        }
      else
        {
          RINode *child = ri_new_node(key + i, value);

          ri_add_child(root, child);
          ret = 1;
        }
    }
  else if (i == keylen && i == nodelen)
    {
      /* exact match */
      if (!root->num_values)
        ret = 1;
      ri_add_value(root, value);
    }
  else if (i > 0 && i < nodelen)
    {
      RINode *old_tree;
      gchar *new_key;

      /* we need to split the current node */
      old_tree = ri_new_empty_node(root->key + i);
      if (root->num_children)
        {
          old_tree->children = root->children;
          old_tree->num_children = root->num_children;
          root->children = NULL;
          root->num_children = 0;
        }

      if (root->num_values)
        {
          memcpy(old_tree->values, root->values, root->num_values * sizeof(RIValue));
          old_tree->num_values = root->num_values;
          memset(root->values, 0, root->num_values * sizeof(RIValue));
          root->num_values = 0;
        }

      new_key = g_strndup(root->key, i);
      g_free(root->key);
      root->key = new_key;
      root->keylen = i;

      ri_add_child(root, old_tree);

      if (i < keylen)
        {
          /* we add a new sub tree */
          RINode *child = ri_new_node(key + i, value);

          ri_add_child(root, child);
        }
      else
        {
          /* the split is us */
          ri_add_value(root, value);
        }
      ret = 1;
    }
  else
    {
      /* simply a new children */
      RINode *child = ri_new_node(key + i, value);

      ri_add_child(root, child);
      ret = 1;
    }

  return ret;
}

/**
 * ri_new_node:
 */
RINode *
ri_new_empty_node(const gchar *key)
{
  assert(key);
  RINode *node = g_new(RINode, 1);

  node->key = g_strdup(key);
  node->keylen = strlen(key);

  node->num_children = 0;
  node->children = NULL;
  node->num_values = 0;
  node->size = -1;

  if (node->keylen > MAX_KEYLEN)
    {
      node->key[MAX_KEYLEN+1] = 0;
      ri_add_child(node, ri_new_empty_node(key+MAX_KEYLEN+1));
    }

  return node;
}

RINode *
ri_new_node(const gchar *key, RIValue value)
{
  RINode *node = ri_new_empty_node(key);

  ri_add_value(node, value);

  return node;
}

void
ri_free_node(RINode *node)
{
  gint i;

  for (i = 0; i < node->num_children; i++)
    ri_free_node(node->children[i]);

  if (node->children)
    g_free(node->children);

  if (node->key)
    g_free(node->key);

  g_free(node);
}

static gint
ri_update_size(RINode *node)
{
  gint32 size =
   sizeof(node->keylen) +
   node->keylen +
   sizeof(node->num_values) +
   node->num_values +
   sizeof(node->num_children);

  for (gint32 i=0; i < node->num_children; i++)
    {
      size += sizeof(size) + ri_update_size(node->children[i]);
    }
  return node->size = size;
}

static gboolean
ri_serialize_node(const RINode *node, FILE *fd)
{
  assert(node);

  guint32 size = g_htonl(node->size);

  if ((fwrite(&size, 1, 4, fd) < 4) ||
      (fwrite(&node->keylen, 1, 1, fd) < 1) ||
      (fwrite(node->key, 1, node->keylen, fd) < node->keylen) ||
      (fwrite(&node->num_values, 1, 1, fd) < 1) ||
      (fwrite(&node->values, 1, node->num_values, fd) < node->num_values) ||
      (fwrite(&node->num_children, 1, 1, fd) < 1))
    {
      return FALSE;
    }

  for (int i = 0; i < node->num_children; i++)
    {
      if (!ri_serialize_node(node->children[i], fd))
        return FALSE;
    }
  return TRUE;
}

gboolean
ri_serialize(RINode *root, FILE *f)
{
  assert(f);
  ri_update_size(root);
  return ri_serialize_node(root, f);
}
