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

#include <zorp/zorp.h>

#include <glib.h>
#include <dirent.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include <zorp/urlfilter_blacklist.h>

#include "radixi.h"

typedef struct
{
  gchar *name;
  guint8 id;
  GTree *expressions;
} Category_t;

typedef struct
{
  GTree *categories;
  RINode *tree;
} BlackList_t;

static int
z_blgen_str_compare(gconstpointer a, gconstpointer b)
{
  return strcmp(static_cast<const char *>(a), static_cast<const char *>(b));
}

Category_t *
z_blgen_create_category(const char *category, guint8 id)
{
  Category_t *ret = static_cast<Category_t *>(g_malloc0(sizeof(Category_t)));
  ret->name = g_strdup(category);
  ret->id = id;
  ret->expressions = g_tree_new(z_blgen_str_compare);
  return ret;
}

BlackList_t *
z_blgen_create_blacklist()
{
  BlackList_t *ret = static_cast<BlackList_t *>(g_malloc0(sizeof(BlackList_t)));
  ret->tree = ri_new_empty_node("");
  ret->categories = g_tree_new(z_blgen_str_compare);
  return ret;
}

void
z_blgen_destroy_blacklist(BlackList_t *blacklist)
{
  g_tree_destroy(blacklist->categories);
  ri_free_node(blacklist->tree);
  g_free(blacklist);
}

void
z_blgen_process_urls(BlackList_t *blacklist, Category_t *category, const gchar *line)
{
  const gint len = strlen(line);
  gchar *rev_domain = strdup(line);
  gchar *end = strchr(rev_domain, '/');
  if (end == 0)
    {
      g_free(rev_domain);
      return;
    }
  else end--;

  gchar *start = rev_domain;
  for (; end > start; end--, start++)
    {
       gchar temp = *start;
       *start = *end;
       *end = temp;
    }

  ri_insert_node(blacklist->tree, rev_domain, len, category->id);
  g_free(rev_domain);
}

void
z_blgen_process_domains(BlackList_t *blacklist, Category_t *category, const gchar *line)
{
  gint i;
  const gint len = strlen(line);
  gchar *rev_domain = static_cast<gchar *>(g_malloc(len+2));
  rev_domain[len] = '/';
  rev_domain[len+1] = 0;
  for (i = 0; i < len; i++)
    {
      rev_domain[len-i-1] = line[i];
    }

  ri_insert_node(blacklist->tree, rev_domain, len+1, category->id);
  g_free(rev_domain);
}

void
z_blgen_process_expressions(BlackList_t * /* blacklist */, Category_t *category, const gchar *line)
{
  g_tree_insert(category->expressions, g_strdup(line), static_cast<gpointer>(0));
}

gint
z_blgen_process_file(BlackList_t *blacklist, const gchar *path, Category_t *category, const gchar* type)
{
  struct
    {
      gchar const *name; void (*f)(BlackList_t *, Category_t *, const gchar *);
    } *i, map[] =
    {
      {"expressions", z_blgen_process_expressions},
      {"urls", z_blgen_process_urls},
      {"domains", z_blgen_process_domains},
      {0, 0}
    };
  gchar filename[512];
  g_snprintf(filename, 512, (const char *)"%s/%s/%s", path, category->name, type);
  FILE *f = fopen(filename, "r");
  if (!f)
    {
      return 0;
    }
  while (!feof(f))
    {
      gchar line[4096];
      if (fgets(line, 4096, f))
        {
          if (line[0] == '#')
            continue;
          gint end = strlen(line) - 1;
          if (line[end] == '\n') line[end] = 0;
          for (i=map; i->name; i++)
            {
              if (strcmp(type, i->name) == 0) i->f(blacklist, category, line);
            }
        }
    }
  fclose(f);
  return 0;
}

gint
z_blgen_add_category(BlackList_t *blacklist, const gchar* path, gchar *category)
{
  gchar dirname[512];

  g_snprintf(dirname, 512, (const char *)"%s/%s", path, category);
  if (g_tree_nnodes(blacklist->categories)>MAX_CATEGORIES)
    {
      fprintf(stderr, "Ignoring %s: too many categories", dirname);
      return 1;
    }
  DIR *dir = opendir(dirname);
  if (!dir)
    {
      fprintf(stderr, "Can't enter directory %s\n", dirname);
      return 1;
    }
  Category_t *category_value;
  if (!(category_value = static_cast<Category_t *>(g_tree_lookup(blacklist->categories, category))))
    {
      category_value = z_blgen_create_category(category, g_tree_nnodes(blacklist->categories));
      g_tree_insert(blacklist->categories, category, static_cast<gpointer>(category_value));
    }

  struct dirent *d;
  while ((d = readdir(dir)))
    {
      if (d->d_name[0] == '0')
        continue;
      gchar buf[512];
      g_snprintf(buf, 512, (const char *)"%s/%s/%s", path, category, d->d_name);
      struct stat s;
      stat(buf, &s);
      if (!S_ISREG(s.st_mode))
        continue;
      if (z_blgen_process_file(blacklist, path, category_value, d->d_name))
        {
          closedir(dir);
          return 1;
        }
    }
  closedir(dir);
  return 0;
}

gint
z_blgen_scan_blacklist(BlackList_t *blacklist, const gchar *dirname)
{
  DIR *dir = opendir(dirname);
  if (!dir)
    {
      fprintf(stderr, "Can't enter directory %s\n", dirname);
      return 1;
    }
  struct dirent *d;
  while ((d = readdir(dir)))
    {
      if (d->d_name[0] == '.')
        continue;
      gchar buf[512];
      g_snprintf(buf, 512, (const char *)"%s/%s", dirname, d->d_name);
      struct stat s;
      stat(buf, &s);
      if (!S_ISDIR(s.st_mode))
        continue;
      if (z_blgen_add_category(blacklist, dirname, d->d_name))
        {
          closedir(dir);
          return 1;
        }
    }
  closedir(dir);
  return 0;
}

BlackList_t *
z_blgen_load_blacklist(gint dir_count, gchar **dirname)
{
  BlackList_t *blacklist = z_blgen_create_blacklist();
  while (dir_count--)
    {
      if (z_blgen_scan_blacklist(blacklist, dirname[dir_count]))
        return 0;
    }
  return blacklist;
}

typedef struct {
  FILE *f;
  gint err;
} TraverseData;

gboolean
z_blgen_expression_traverse(gpointer key, gpointer /* value */, gpointer data)
{
  gchar *expression = (gchar*) key;
  TraverseData *d = (TraverseData*) data;
  guint32 BE_expression_len = g_htons(strlen(expression));

  if ((fwrite(&BE_expression_len, 2, 1, d->f) < 1) ||
      (fwrite(expression, strlen(expression), 1, d->f) < 1))
    {
      d->err = 1;
      return TRUE;
    }

  return FALSE;
}

gboolean
z_blgen_category_traverse(gpointer /* key */, gpointer value, gpointer data)
{
  TraverseData *d = (TraverseData*) data;
  Category_t *category = (Category_t*)value;
  guint8 name_len = strlen(category->name);
  guint16 BE_num_expressions = g_htons(g_tree_nnodes(category->expressions));

  if ((fwrite(&category->id, 1, 1, d->f) < 1) ||
      (fwrite(&name_len, 1, 1, d->f) < 1) ||
      (fwrite(category->name, name_len, 1, d->f) < 1) ||
      (fwrite(&BE_num_expressions, 2, 1, d->f) < 1))
    {
      d->err = 1;
      return TRUE;
    }

  g_tree_foreach(category->expressions, z_blgen_expression_traverse, static_cast<gpointer>(d));

  return FALSE;
}

gint
z_blgen_blacklist_category_serialize(BlackList_t *blacklist, FILE *f)
{
  gint num_categories = g_tree_nnodes(blacklist->categories);

  if (fwrite(&num_categories, 1, 1, f) < 1)
    return -1;

  TraverseData d = { f, 0 };

  g_tree_foreach(blacklist->categories, z_blgen_category_traverse, static_cast<gpointer>(&d));

  return d.err;
}

gint
z_blgen_generate_blacklist_file(BlackList_t *blacklist, gchar *filename)
{
  FILE *f = fopen(filename, "w");
  if (!f)
    {
      fprintf(stderr, "Can't open output file %s.\n", filename);
      return 3;
    }

  guint32 BE_format = g_htonl(FORMAT_MAGIC);
  guint version = FORMAT_VERSION;

  if ((fwrite(&BE_format, 4, 1, f) < 1) ||
      (fwrite(&version, 1, 1, f) < 1) ||
      (z_blgen_blacklist_category_serialize(blacklist, f) < 0) ||
      (!ri_serialize(blacklist->tree, f)))
    {
      fclose(f);
      fprintf(stderr, "Error while writing to %s\n", filename);
      return 3;
    }

  fclose(f);
  return 0;
}

int
main(int argc, char **argv)
{
  int ret = 0;

  if (argc < 3)
    {
      printf("Usage: %s <output> <input> [input...]\n"
             "    where output is the name of the generated file,\n"
             "          input is the directory defining blacklist categories\n\n"
             , argv[0]);
      return 1;
    }
  BlackList_t *blacklist = z_blgen_load_blacklist(argc-2, argv+2);
  if (!blacklist)
    {
      fprintf(stderr, "Error while parsing blacklist data\n");
      return 2;
    }
  ret = z_blgen_generate_blacklist_file(blacklist, argv[1]);
  z_blgen_destroy_blacklist(blacklist);

  return ret;
}
