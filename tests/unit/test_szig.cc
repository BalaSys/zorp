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

#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

#include <zorp/zorp.h>
#include <zorpll/thread.h>
#include <zorp/szig.h>
#include <time.h>

/*
 * TODO: test per-zone service counters
 * TODO: test license address limit counters
 */

#define NUM_CONNS 900
#define NUM_THREADS 900
/* The maximum number of threads will be the number of threads plus one (szig's own thread) */
#define MAX_THREADS (NUM_THREADS + 1)
#define TICK_TIME 5
#define S_1_MIN 60
#define S_5_MIN (5 * S_1_MIN)
#define S_15_MIN (15 * S_1_MIN)
#define TICKS_PER_1_MIN (60 / TICK_TIME)
#define TICKS_PER_5_MIN (300 / TICK_TIME)
#define TICKS_PER_15_MIN (900 / TICK_TIME)
constexpr int LONG_NAME_LENGTH = 300;

static gint
init_szig(void)
{

  z_thread_init();
  z_szig_init("test_szig");

  return 0;
}

static gint
check_szig_long(const char * const node_name, glong expected)
{
  const ZSzigNode * const node = z_szig_tree_lookup(node_name, FALSE, NULL, NULL);

  if (!node || (node->value.type != Z_SZIG_TYPE_LONG))
    {
      fprintf(stderr, "non-existent node or type mismatch; name='%s'\n", node_name);
      return 1;
    }

  if (node->value.u.long_value != expected)
    {
      fprintf(stderr, "value mismatch; name='%s', value='%ld', expected='%ld'\n",
              node_name, node->value.u.long_value, expected);
      return 1;
    }

  return 0;
}


static void
generate_tick(guint tick)
{
  GTimeVal time;

  time.tv_sec = tick * 5;
  time.tv_usec = 0;

  z_szig_event(Z_SZIG_TICK, z_szig_value_new_time(&time));
}

static void
forward_time(guint ticks)
{
  static guint last = 0;
  guint i;

  for (i = 0; i < ticks; i++)
    generate_tick(last + i);

  last += ticks;
}

static void
generate_connections(void)
{
  guint i;

  fprintf(stdout, "generating connection events\n");

  for (i = 0; i < NUM_CONNS; i++)
    {
      z_szig_event(Z_SZIG_SERVICE_COUNT,
                   z_szig_value_new_props("test_service",
                                          "session_number", z_szig_value_new_long(i + 1),
                                          "sessions_running", z_szig_value_new_long(NUM_CONNS - i),
                                          NULL));

      z_szig_event(Z_SZIG_CONNECTION_PROPS,
                   z_szig_value_new_connection_props("test_service", i, 0, 0,
                                                     "auth_user", "testuser",
                                                     "auth_info", "",
                                                     "auth_groups", "testgroup",
                                                     "client_zone", "czone",
                                                     "server_zone", "szone",
                                                     NULL));

      z_szig_event(Z_SZIG_CONNECTION_STOP,
                   z_szig_value_new_connection_props("test_service", i, 0, 0,
                                                     NULL));
    }
}

static gint
check_connection_rates(glong avg1, glong avg5, glong avg15)
{
  gint failed = 0;

  fprintf(stdout, "checking connection rate averages; avg1='%ld', avg5='%ld', avg15='%ld'\n",
          avg1, avg5, avg15);

  failed = check_szig_long("service.test_service.session_number", NUM_CONNS);
  if (!failed)
    failed = check_szig_long("service.test_service.sessions_running", 1);
  if (!failed)
    failed = check_szig_long("service.test_service.sessions_max", NUM_CONNS);
  if (!failed)
    failed = check_szig_long("service.test_service.rate_max", NUM_CONNS / TICK_TIME);
  if (!failed)
    failed = check_szig_long("service.test_service.rate_avg1", avg1);
  if (!failed)
    failed = check_szig_long("service.test_service.rate_avg5", avg5);
  if (!failed)
    failed = check_szig_long("service.test_service.rate_avg15", avg15);

  return failed;
}

static int
check_thread_counters(void)
{
  fprintf(stdout, "testing thread counters\n");

  /* preconditions */
  if (check_szig_long("stats.thread_number", NUM_THREADS + 3))
    return 1;
  if (check_szig_long("stats.threads_running", 1))
    return 1;
  if (check_szig_long("stats.threads_max", MAX_THREADS))
    return 1;

  z_szig_event(Z_SZIG_THREAD_START, NULL);
  sleep(1);

  if (check_szig_long("stats.thread_number", NUM_THREADS + 4))
    return 1;
  if (check_szig_long("stats.threads_running", 2))
    return 1;
  if (check_szig_long("stats.threads_max", MAX_THREADS))
    return 1;

  z_szig_event(Z_SZIG_THREAD_START, NULL);
  sleep(1);

  if (check_szig_long("stats.thread_number", NUM_THREADS + 5))
    return 1;
  if (check_szig_long("stats.threads_running", 3))
    return 1;
  if (check_szig_long("stats.threads_max", MAX_THREADS))
    return 1;

  z_szig_event(Z_SZIG_THREAD_STOP, NULL);
  sleep(1);

  if (check_szig_long("stats.thread_number", NUM_THREADS + 5))
    return 1;
  if (check_szig_long("stats.threads_running", 2))
    return 1;
  if (check_szig_long("stats.threads_max", MAX_THREADS))
    return 1;

  z_szig_event(Z_SZIG_THREAD_STOP, NULL);
  sleep(1);

  if (check_szig_long("stats.thread_number", NUM_THREADS + 5))
    return 1;
  if (check_szig_long("stats.threads_running", 1))
    return 1;
  if (check_szig_long("stats.threads_max", MAX_THREADS))
    return 1;

  return 0;
}

static void
generate_threads(void)
{
  guint i;

  fprintf(stdout, "generating threads\n");

  for (i = 0; i < NUM_THREADS; i++)
    {
      z_szig_event(Z_SZIG_THREAD_START, NULL);
    }
  for (i = 0; i < NUM_THREADS; i++)
    {
      z_szig_event(Z_SZIG_THREAD_STOP, NULL);
    }
}

static gint
check_thread_rates(glong avg1, glong avg5, glong avg15)
{
  gint failed = 0;

  /* the SZIG thread is always running and skews statistics */

  fprintf(stdout, "checking thread rate averages; avg1='%ld', avg5='%ld', avg15='%ld'\n",
          avg1, avg5, avg15);

  failed = check_szig_long("stats.thread_number", NUM_THREADS + 3);
  if (!failed)
    failed = check_szig_long("stats.threads_running", 1);
  if (!failed)
    failed = check_szig_long("stats.threads_max", MAX_THREADS);
  if (!failed)
    failed = check_szig_long("stats.thread_rate_max", NUM_THREADS / TICK_TIME);
  if (!failed)
    failed = check_szig_long("stats.thread_rate_avg1", avg1);
  if (!failed)
    failed = check_szig_long("stats.thread_rate_avg5", avg5);
  if (!failed)
    failed = check_szig_long("stats.thread_rate_avg15", avg15);

  return failed;
}

static int
check_service_nodes_exists(void)
{
  std::string service_name;
  service_name.reserve(LONG_NAME_LENGTH);
  for (int i = 0; i < LONG_NAME_LENGTH; ++i)
    service_name += ('a' + (i % ('z'-'a'+1)));

  z_szig_event(Z_SZIG_SERVICE_COUNT,
               z_szig_value_new_props(service_name.c_str(),
                                      "session_number", z_szig_value_new_long(1),
                                      "sessions_running", z_szig_value_new_long(0),
                                      NULL));

  z_szig_event(Z_SZIG_CONNECTION_PROPS,
               z_szig_value_new_connection_props(service_name.c_str(), 0, 0, 0,
                                                 "client_zone", "czone",
                                                 "server_zone", "szone",
                                                 NULL));

  z_szig_event(Z_SZIG_CONNECTION_STOP,
               z_szig_value_new_connection_props(service_name.c_str(), 0, 0, 0, NULL));

  sleep(1);

  service_name.insert(0, "service.").append(".");
  const std::string items[] = {"sessions_max", "sessions_running", "session_number",
                               "inbound_zones", "outbound_zones"};
  for (const auto &item : items)
    {
      if (!z_szig_tree_lookup((service_name + item).c_str(), FALSE, NULL, NULL)) return 1;
    }

  return 0;
}

BOOST_AUTO_TEST_CASE(test_szig)
{
  BOOST_CHECK(!init_szig());

  /* szig creates a callback that calls z_szig_event with Z_SZIG_THREAD_START when a thread is started,
   * then starts a thread.
   * Wait 1 sec to make sure the callback is called and the test starts with a consistent state
   * (stats.threads_running == 3) */
  sleep(1);

  /* szig thread count has a skew of 2 that offsets the threads started by Zorp core
   * before SZIG initialization: this makes testing thread counters and averages
   * difficult, so we generate two thread stop events here */
  z_szig_event(Z_SZIG_THREAD_STOP, NULL);
  z_szig_event(Z_SZIG_THREAD_STOP, NULL);

  fprintf(stdout, "checking service nodes exists\n");
  BOOST_CHECK(!check_service_nodes_exists());


  fprintf(stdout, "checking connection rate statistics\n");
  /* generate NUM_CONNS connections right now */
  generate_connections();

  /* test sliding window */
  fprintf(stdout, "fast-forwarding one minute\n");
  forward_time(TICKS_PER_1_MIN);
  sleep(1);
  BOOST_CHECK(!check_connection_rates(NUM_CONNS / S_1_MIN, NUM_CONNS / S_5_MIN, NUM_CONNS / S_15_MIN));

  fprintf(stdout, "fast-forwarding four minutes\n");
  forward_time(TICKS_PER_5_MIN - TICKS_PER_1_MIN);
  sleep(1);
  BOOST_CHECK(!check_connection_rates(0, NUM_CONNS / S_5_MIN, NUM_CONNS / S_15_MIN));

  fprintf(stdout, "fast-forwarding ten minutes\n");
  forward_time(TICKS_PER_15_MIN - TICKS_PER_5_MIN);
  sleep(1);
  BOOST_CHECK(!check_connection_rates(0, 0, NUM_CONNS / S_15_MIN));

  fprintf(stdout, "fast-forwarding one minute\n");
  forward_time(TICKS_PER_1_MIN);
  sleep(1);
  BOOST_CHECK(!check_connection_rates(0, 0, 0));

  fprintf(stdout, "checking thread rate statistics\n");
  /* start and stop NUM_THREADS threads */
  generate_threads();

  /* test sliding window */
  fprintf(stdout, "fast-forwarding one minute\n");
  forward_time(TICKS_PER_1_MIN);
  sleep(1);
  BOOST_CHECK(!check_thread_rates(NUM_THREADS / S_1_MIN, NUM_THREADS / S_5_MIN, NUM_THREADS / S_15_MIN));

  fprintf(stdout, "checking thread counters\n");
  BOOST_CHECK(!check_thread_counters());
}
