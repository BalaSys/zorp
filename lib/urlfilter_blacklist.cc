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

#include <zorp/urlfilter_blacklist.h>
#include <zorpll/log.h>
#include <zorp/zorp.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <regex.h>
#include <glib.h>

#include <vector>

typedef guint8 ZBLValue;

struct ZBLNodeValue
{
  gint8 size;
  ZBLValue values[0];
};

/*
 *  Generic ZBLTreeData access/manipulation functions
 */

static void
z_bl_tree_advance(ZBLTreeData *tree, guint32 n)
{
  tree->data += n;
  tree->size -= n;
}

static gint32
z_bl_read_gint32(ZBLTreeData *tree)
{
  gint32 ret = g_ntohl(*(gint32*)tree->data);
  z_bl_tree_advance(tree, 4);
  return ret;
}

static guint16
z_bl_read_guint16(ZBLTreeData *tree)
{
  guint16 ret = g_ntohs(*(guint16*)tree->data);
  z_bl_tree_advance(tree, 2);
  return ret;
}

static guint8
z_bl_read_guint8(ZBLTreeData *tree)
{
  guint8 ret = (*(guint8*)tree->data);
  z_bl_tree_advance(tree, 1);
  return ret;
}

static std::string
z_bl_read_string(ZBLTreeData *tree, guint32 len)
{
  const char *p = reinterpret_cast<const char*>(tree->data);
  z_bl_tree_advance(tree, len);
  return std::string(p, len);
}

static std::string
z_bl_read_string8(ZBLTreeData *tree)
{
  guint8 len = z_bl_read_guint8(tree);
  return z_bl_read_string(tree, len);
}

static std::string
z_bl_read_string16(ZBLTreeData *tree)
{
  guint16 len = z_bl_read_guint16(tree);
  return z_bl_read_string(tree, len);
}

static gint32
z_bl_read_size(ZBLTreeData *tree)
{
  return z_bl_read_gint32(tree);
}

static guint8
z_bl_read_num_children(ZBLTreeData *tree)
{
  return z_bl_read_guint8(tree);
}

/*
 * ZBLCategory: collection of regexes
 */

class ZBLRegex
{
  std::string expression;
  regex_t regex;

public:
  class Exception: public std::exception
  {
    int errcode;
    gchar error[256];
    std::string expression;

  public:
    virtual const char* what() const noexcept
      {
        return error;
      }

    virtual const char* get_expression() const noexcept
      {
        return expression.c_str();
      }

    Exception(const ZBLRegex *rgx, int code) : errcode(code), expression(rgx->expression)
    {
      regerror(errcode, &rgx->regex, error, sizeof(error));
    }
  };

  ZBLRegex(ZBLTreeData *tree);
  ~ZBLRegex();
  int exec(const char *string, size_t nmatch, regmatch_t pmatch[], int eflags);
  int exec(const char *string, int eflags)
    {
      return exec(string, 0, NULL, eflags);
    };
};


ZBLRegex::ZBLRegex(ZBLTreeData *tree) : expression(z_bl_read_string16(tree))
{
  int status = regcomp(&regex, expression.c_str(), REG_EXTENDED | REG_NOSUB);
  if (status)
    throw ZBLRegex::Exception(this, status);
}

ZBLRegex::~ZBLRegex()
{
  regfree(&regex);
}

int
ZBLRegex::exec(const char *string, size_t nmatch, regmatch_t pmatch[], int eflags)
{
  return regexec(&regex, string, nmatch, pmatch, eflags);
}

class ZBLCategory
{
  public:
  static void wrap_destructor(gpointer value);
  std::string name;
  std::vector<ZBLRegex> regexes;

  ZBLCategory(ZBLTreeData *tree);
  const std::string& get_name()
    {
      return name;
    };
};


ZBLCategory::ZBLCategory(ZBLTreeData *tree) :
  name(z_bl_read_string8(tree))
{
  guint num_expressions = z_bl_read_guint16(tree);

  regexes.reserve(num_expressions);
  for (guint j = 0; j < num_expressions; j++)
    {
      try
        {
          regexes.emplace_back(tree);
        }
      catch (ZBLRegex::Exception &e)
        {
          z_log(NULL, CORE_ERROR, 1, "Error compiling regular expression; expression='%s', error='%s'",
                e.get_expression(), e.what());
        }
    }
}

void
ZBLCategory::wrap_destructor(gpointer value)
{
  ZBLCategory *category = (ZBLCategory*) value;
  delete category;
}

/*
 * Structure specific ZBLTreeData access/manipulation functions
 */

typedef struct
{
  guint8 size;
  gchar data[0];
} Key;

static Key *
z_bl_read_key(ZBLTreeData *tree)
{
  Key *key = (Key*) tree->data;
  z_bl_tree_advance(tree, key->size + sizeof(key->size));
  return key;
}

static ZBLNodeValue *
z_bl_read_values(ZBLTreeData *tree)
{
  ZBLNodeValue *values = (ZBLNodeValue*)tree->data;
  z_bl_tree_advance(tree, values->size * sizeof(ZBLValue) + sizeof(values->size));
  if (!values->size)
    return NULL;
  return values;
}

static gint
z_bl_intcmp(gconstpointer a, gconstpointer b, gpointer  /* userdata */)
{
  return (gchar *)a - (gchar *)b;
}

static int
z_bl_read_categories(ZBLTreeData *tree)
{
  gint32 magic = z_bl_read_gint32(tree);
  gint8 version = z_bl_read_guint8(tree);

  if (magic != FORMAT_MAGIC)
    return -1;
  if (version != FORMAT_VERSION)
    return -2;

  gsize num_categories = z_bl_read_guint8(tree);
  tree->categories = g_tree_new_full(z_bl_intcmp, 0, 0, ZBLCategory::wrap_destructor);

  for (guint i = 0; i < num_categories; i++)
    {
      glong category_id = z_bl_read_guint8(tree);
      ZBLCategory * category = new ZBLCategory(tree);
      g_tree_insert(tree->categories, (gpointer)category_id, category);
      if (tree->size < 0)
        return -3;
    }
  return 0;
}

/**
 * find_values:
 * @param tree the part of the tree to match against
 * @param key the key to match
 * @param[out] matching_categories array of categories where the matching ones are registered
 *
 * Helper function for z_bl_match. Note that it modifies the tree structure.
 */

static void
z_bl_find_values(ZBLTreeData *tree, const gchar *key, guint32 *matching_categories)
{
  gint8 *node_start = tree->data;
  const gsize tree_size = tree->size;
  const gint32 node_size = z_bl_read_size(tree);
  if (node_size > tree->size)
    {
      z_log(NULL, CORE_ERROR, 1, "Invalid URL filter database, tree size mismatch; "
            "node_size='%d', tree_size='%d'", node_size, tree->size);
      return;
    }
  Key *node_key = z_bl_read_key(tree);
  ZBLNodeValue *values = z_bl_read_values(tree);
  gint8 num_children = z_bl_read_num_children(tree);

  gint keysize = strlen(key);

  /* current pattern is longer than the string */
  if (keysize < node_key->size)
    {
      goto bailout;
    }
  gint i;
  for (i = 0; i < node_key->size && node_key->data[i] == key[i]; i++);
  if (i < node_key->size)
    {
      if (node_key->data[i] == '/' && key[i] == '.')
        {
          key = strchr(key, '/');
          if (!key)
            goto bailout;
          keysize = strlen(key);
          if (keysize < node_key->size - i)
            {
              goto bailout;
            }
          if (memcmp(node_key->data + i, key, node_key->size - i))
            {
              goto bailout;
            }
        }
      else goto bailout;
    }

  if (keysize > node_key->size)
    {
      /* check if there's a longer match */
      while (num_children--)
        {
          z_bl_find_values(tree, key+node_key->size, matching_categories);
        }
    }
  if (!values)
    {
      /* The current top node does not match, moving to the next sibling node in the tree. */
      goto bailout;
    }
  for (i = 0; i < values->size; i++)
    {
      matching_categories[values->values[i]]++;
    }
  return;

bailout:
  /* moving to next sibling node */
  tree->data = node_start + node_size + sizeof(node_size);
  tree->size = tree_size - node_size - sizeof(node_size);
  return;
}

static void
z_bl_find_values_regex(const ZBLTreeData *tree, const gchar *key, guint32 *matching_categories)
{
  gulong i;
  guint num_categories = static_cast<guint>(g_tree_nnodes(tree->categories));
  for (i = 0; i < num_categories; i++)
    {
      ZBLCategory *category = ((ZBLCategory*)g_tree_lookup(tree->categories, (gpointer)i));
      for (auto &regex : category->regexes)
        {
          if (regex.exec(key, 0) == 0)
            matching_categories[i]++;
        }
    }
}

ZBLTreeData::~ZBLTreeData()
{
  g_tree_destroy(categories);
  assert(munmap(mmap_addr, mmap_size) == 0);
}

/**
 * Match a key against the blacklist.
 * @param tree the blacklist to match against
 * @param key the key to check
 * @param prefix true for prefix matching, false for exact matching
 *
 * If prefix matching is used, the key will match if it has a prefix
 * that's included in the blacklist. With exact matching, matching
 * will be reported only if the key is in the blacklist verbatim.
 *
 * @return the node values if the key is matching. Returns NULL if the key doesn't match.
 */

UrlFilter::Result
UrlFilterBlacklist::z_bl_tree_match(const ZBLTreeData *tree, const gchar *key)
{
  gint num_categories = g_tree_nnodes(tree->categories);
  ZBLTreeData *tmptree = static_cast<ZBLTreeData *>(g_memdup(tree, sizeof(*tree)));
  guint32 *matching_categories = g_new0(guint32, num_categories);
  memset(matching_categories, 0, sizeof(*matching_categories) * num_categories);

  z_bl_find_values_regex(tree, key, matching_categories);

  /* reverse the domain part */
  gchar *newkey = strdup(key);
  gchar *domain_end = strchr(newkey, '/');
  if (domain_end)
    {
      domain_end--;
      gchar *start = newkey;
      for (; start < domain_end; start++, domain_end--)
        {
          gchar temp = *start;
          *start = *domain_end;
          *domain_end = temp;
        }
    }

  z_bl_find_values(tmptree, newkey, matching_categories);

  g_free(newkey);
  g_free(tmptree);

  glong i,j=0;
  UrlFilter::Result ret;
  for (i = 0; i < num_categories && j < MAX_CATEGORIES; i++)
    {
      if (matching_categories[i])
        {
          ret.category[j++] = ((ZBLCategory*)g_tree_lookup(tree->categories,
                                                                     (gpointer)i))->get_name().c_str();
        }
    }
  g_free(matching_categories);
  ret.num_categories = j;

  return ret;
}

/**
 * Load a blacklist lookup tree from disk.
 * @param filename name of the blacklist data file, generated by zorpblgen
 *
 * mmaps the supplied blacklist file and wraps it into the ZBLTreeData structure.
 *
 * @return The blacklist structure. In case of an error, returns NULL.
 */
std::unique_ptr<ZBLTreeData>
UrlFilterBlacklist::z_bl_tree_load(const gchar *filename)
{
  gint ret;
  z_log(NULL, CORE_INFO, 5, "Loading URL filter database; filename='%s'", filename);

  int fd = open(filename, O_RDONLY);
  if (fd == -1)
    {
      z_log(NULL, CORE_ERROR, 1, "Failed to open URL filter database; filename='%s'", filename);
      return NULL;
    }

  struct stat s;
  fstat(fd, &s);

  auto tree = std::make_unique<ZBLTreeData>();

  gpointer m = mmap(0, s.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED)
    {
      z_log(NULL, CORE_ERROR, 1, "Failed to map URL filter database into memory; filename='%s', error='%s'",
            filename, g_strerror(errno));
      close(fd);
      return NULL;
    }

  close(fd);
  tree->data = tree->mmap_addr = (gint8 *)m;
  tree->size = tree->mmap_size = s.st_size;
  tree->st_dev = s.st_dev;
  tree->st_inode = s.st_ino;

  if ((ret = z_bl_read_categories(tree.get()) < 0))
    {
      /*LOG
        This message indicates that the url filter database can't be loaded.
        This could be because of a bad file format, version mismatch or an
        error in the generated database.
        */
      z_log(NULL, CORE_ERROR, 1, "Failed to parse URL filter database; filename='%s', error='%s'", filename,
          (ret == -1) ? "Wrong file format" :
         ((ret == -2) ? "Wrong database version" :
                        "Internal database error") );
      return NULL;
    }
  return tree;
}

G_LOCK_DEFINE_STATIC(z_bl_mutex);
static std::unique_ptr<ZBLTreeData> z_bl_tree;
static time_t z_bl_last_db_check = 0;

#define ZORP_URLFILTER_DB_FILE ZORP_STATE_DIR "/urlfilter/urlfilter.db"
#define ZORP_URLFILTER_DB_CHECK_INTERVAL 60

UrlFilter::Result
UrlFilterBlacklist::z_bl_lookup(const gchar *key)
{
  UrlFilter::Result res;

  z_enter();

  G_LOCK(z_bl_mutex);

  if (!z_bl_tree)
    {
      z_bl_tree = z_bl_tree_load(ZORP_URLFILTER_DB_FILE);
    }
  else
    {
      struct stat s;
      time_t now = time(NULL);

      if (z_bl_last_db_check + ZORP_URLFILTER_DB_CHECK_INTERVAL < now)
        {
          if ((stat(ZORP_URLFILTER_DB_FILE, &s) == 0)
              && ((s.st_dev != z_bl_tree->st_dev)
                  || (s.st_ino != z_bl_tree->st_inode)))
            {
              if (auto new_tree = z_bl_tree_load(ZORP_URLFILTER_DB_FILE))
                z_bl_tree = std::move(new_tree);
            }

          z_bl_last_db_check = now;
        }
    }

  if (!z_bl_tree)
    {
      G_UNLOCK(z_bl_mutex);
      z_log(NULL, CORE_ERROR, 1, "Failed to load URL filter database; filename='%s'", ZORP_URLFILTER_DB_FILE);
      return res;
    }

  G_UNLOCK(z_bl_mutex);

  res = z_bl_tree_match(z_bl_tree.get(), key);

  z_leave();

  return res;
}

UrlFilterBlacklist::UrlFilterBlacklist()
{
  initialized = true;
}

UrlFilterBlacklist::~UrlFilterBlacklist()
{
}

UrlFilter::Result
UrlFilterBlacklist::lookup_url(std::string_view url)
{
  return z_bl_lookup(url.data());
}
