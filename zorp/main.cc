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

#include <zorp/zorp.h>
#include <zorpll/io.h>
#include <zorpll/stream.h>
#include <zorp/policy.h>
#include <zorpll/registry.h>
#include <zorpll/thread.h>
#include <zorpll/log.h>
#include <zorpll/cap.h>
#include <zorpll/ssl.h>
#include <zorp/dgram.h>
#include <zorp/tpsocket.h>
#include <zorpll/poll.h>
#include <zorp/szig.h>
#include <zorp/tpsocket.h>
#include <zorp/dispatch.h>
#include <zorpll/process.h>
#include <zorpll/blob.h>
#ifdef HAVE_LINUX_NETLINK_H
#include <zorp/ifmonitor.h>
#endif

#include <zorpll/stackdump.h>


#include <zorp/proxy.h>

#include <openssl/rand.h>

#include <sys/types.h>
#include <sys/resource.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <sys/wait.h>

#include <sys/time.h>
#include <unistd.h>

#include <sys/ioctl.h>

#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

#if HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include <sys/termios.h>

#ifdef PREDICTABLE_RANDOM_ENABLED
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#endif

#include "logtags_gperf.c"

static gint
z_logtag_lookup(const gchar *tag, gsize len)
{
  const struct tagid *p = NULL;

  p = LogTagHash::lookup(tag, len);
  if (G_LIKELY(p))
    return p->id;
  else
    return -1;
}

void
z_sigterm_handler(int  /* signo */)
{
  z_main_loop_initiate_termination(TRUE);
}

void __attribute__((const))
z_ignore_signal_handler(int  /* signo */)
{
}

void
z_sighup_handler(int  /* signo */)
{
  z_main_loop_initiate_reload(TRUE);
}

void
z_sigchild_handler(int  /* signo */)
{
  while (waitpid(-1, NULL, WNOHANG) > 0)
    ;
}

void
z_fatal_signal_handler(int signo)
{
  ZSignalContext *p = z_stackdump_get_context(p);
  struct sigaction act;

  memset(&act, 0, sizeof(act));
  act.sa_handler = SIG_DFL;
  sigaction(signo, &act, NULL);

  /*LOG
    This message is logged when Zorp caught a fatal signal.
    Possible reason is bad RAM or other hardware.
   */
  z_log(NULL, CORE_ERROR, 0, "Signal received, stackdump follows; signo='%d'", signo);
  z_mem_trace_stats();
  z_stackdump_log(p);
  kill(getpid(), signo);
}

void
z_sigusr1_handler(int  /* signo */)
{
  usr1_received = 1;
}

void
z_sigusr2_handler(int  /* signo */)
{
  usr2_received = 1;
}

void
z_setup_signals(void)
{
  struct sigaction  act;
  sigset_t          ss;

  sigemptyset(&ss);

  memset(&act, 0, sizeof(act));
  act.sa_handler = z_ignore_signal_handler;
  sigaction(SIGPIPE, &act, NULL);
  sigaddset(&ss, SIGPIPE);

  memset(&act, 0, sizeof(act));
  act.sa_handler = z_sigterm_handler;
  sigaction(SIGTERM, &act, NULL);
  sigaddset(&ss, SIGTERM);
  sigaction(SIGINT, &act, NULL);
  sigaddset(&ss, SIGINT);

  memset(&act, 0, sizeof(act));
  act.sa_handler = z_fatal_signal_handler;
  sigaction(SIGSEGV, &act, NULL);
  sigaddset(&ss, SIGSEGV);
  sigaction(SIGABRT, &act, NULL);
  sigaddset(&ss, SIGABRT);
  sigaction(SIGILL, &act, NULL);
  sigaddset(&ss, SIGILL);

  memset(&act, 0, sizeof(act));
  act.sa_handler = z_ignore_signal_handler;
  sigaction(SIGTRAP, &act, NULL);
  sigaddset(&ss, SIGTRAP);

  memset(&act, 0, sizeof(act));
  act.sa_handler = z_sigchild_handler;
  sigaction(SIGCHLD, &act, NULL);
  sigaddset(&ss, SIGCHLD);

  memset(&act, 0, sizeof(act));
  act.sa_handler = z_sighup_handler;
  sigaction(SIGHUP, &act, NULL);
  sigaddset(&ss, SIGHUP);

  memset(&act, 0, sizeof(act));
  act.sa_handler = z_sigusr1_handler;
  sigaction(SIGUSR1, &act, NULL);
  sigaddset(&ss, SIGUSR1);

  memset(&act, 0, sizeof(act));
  act.sa_handler = z_sigusr2_handler;
  sigaction(SIGUSR2, &act, NULL);
  sigaddset(&ss, SIGUSR2);

  sigprocmask(SIG_UNBLOCK, &ss, NULL);
}

#define ON_OFF_STR(x) (x ? "on" : "off")

void
z_version(void)
{
  printf("%s %s (%s)\n"
         "Config-Date: %s\n"
         "Trace: %s\n"
         "IPOptions: %s\n\n"
         "%s\n"
         ,
         GATEWAY_PRODUCT_NAME,
         BROCHURE_VERSION, VERSION,
         ZORP_CONFIG_DATE,
         ON_OFF_STR(ENABLE_TRACE),
         ON_OFF_STR(ENABLE_IPOPTIONS),
         z_libzorpll_version_info()
         );
}

/* arguments */

#define MAX_SOFT_INSTANCES 128

static const gchar *instance_policy_list[MAX_SOFT_INSTANCES + 1];
static gint instance_count = 1;
static const gchar *policy_file = ZORP_POLICY_FILE;
static gboolean log_escape = FALSE;
static gboolean display_version = FALSE;

static gboolean
z_set_instance_name(const gchar * /* option_name */, const gchar *value, gpointer  /* user_datae */,
                    GError **error)
{
  instance_name = static_cast<const gchar *>(g_strdup(value));
  instance_policy_list[0] = (gchar *) instance_name;
  instance_count = 1;
  g_clear_error(error);
  return TRUE;
}


static gboolean
z_set_virtual_instance_name(const char *option_name, const gchar *value,
                            gpointer  /* user_data */,
                            GError ** /* error */)
{
  if (strcmp(option_name, "--slave") == 0)
    zorp_process_master_mode = FALSE;

  virtual_instance_name = static_cast<const gchar *>(g_strdup(value));

  return TRUE;
}

static gint deadlock_checker_timeout = DEADLOCK_CHECKER_DEFAULT_TIMEOUT;
static GOptionEntry zorp_options[] =
{
  { "as",           'a',                     0, G_OPTION_ARG_CALLBACK, reinterpret_cast<gpointer>(z_set_instance_name), "Set instance name", "<instance>" },
  { "master",       0,                       0, G_OPTION_ARG_CALLBACK, reinterpret_cast<gpointer>(z_set_virtual_instance_name), "Run in master mode with the virtual instance name specified", "<virtual-instance>"},
  { "slave",        0,                       0, G_OPTION_ARG_CALLBACK, reinterpret_cast<gpointer>(z_set_virtual_instance_name), "Run in slave mode with the virtual instance name specified", "<virtual-instance>"},
  { "policy",       'p',                     0, G_OPTION_ARG_STRING, &policy_file,          "Set policy file", "<policy>" },
  { "version",      'V',                     0, G_OPTION_ARG_NONE,   &display_version,      "Display version number", NULL },
  { "log-escape",     0,                     0, G_OPTION_ARG_NONE,   &log_escape,           "Escape log messages to avoid non-printable characters", NULL },
  { "deadlock-check-timeout", 0,             0, G_OPTION_ARG_INT,    &deadlock_checker_timeout, "Timeout for deadlock detection queries in seconds", NULL },
  { NULL,             0,                     0, G_OPTION_ARG_NONE,   NULL,                  NULL, NULL }
};

typedef enum
  {
    COMM_PHASE_NONE = 0,
    COMM_PHASE_CONNECT,
    COMM_PHASE_READ,
    COMM_PHASE_MAX
  } ZDeadlockCommPhase;

static const char* z_deadlock_comm_phase_names[COMM_PHASE_MAX + 1] =
  {
    [COMM_PHASE_NONE] = NULL,
    [COMM_PHASE_CONNECT] = "connect",
    [COMM_PHASE_READ] = "read",
    [COMM_PHASE_MAX] = NULL
  };

static const char*
z_deadlock_comm_phase_name(ZDeadlockCommPhase phase)
{
  if (z_deadlock_comm_phase_names[phase])
    return z_deadlock_comm_phase_names[phase];
  else
    return "unknown";
}

static gboolean
z_is_deadlock_szig_error_ignored(ZDeadlockCommPhase phase, int errnum)
{
  gboolean result;

  switch (phase)
    {
    case COMM_PHASE_CONNECT:
      result = (errnum == ECONNREFUSED);
      break;

    case COMM_PHASE_READ:
      result = (errnum == ECONNRESET);
      break;

    default:
      result = FALSE;
      break;
    }

  if (result)
    {
      z_process_message("Ignoring error during SZIG communication; phase='%s', reason='%s'",
                        z_deadlock_comm_phase_name(phase), strerror(errnum));
    }

  return result;
}

static gboolean
zorp_deadlock_checker(void)
{
  struct sockaddr_un unaddr;
  gint fd = -1, len;
  gboolean res = FALSE;
  const gchar *request = "GETVALUE zorp.info.policy.file_stamp\n";
  gchar response[1024];
  struct timeval tv;
  fd_set rdset;

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd == -1)
    {
      z_process_message("Cannot create socket; reason='%s'", strerror(errno));
      goto finish;
    }

  unaddr.sun_family = AF_UNIX;
  snprintf(unaddr.sun_path, sizeof(unaddr.sun_path), "%s.%s", ZORP_SZIG_SOCKET_NAME, virtual_instance_name);
  if (connect(fd, (struct sockaddr *) &unaddr, sizeof(unaddr)) < 0)
    {
      int errnum = errno;
      res = z_is_deadlock_szig_error_ignored(COMM_PHASE_CONNECT, errnum);
      if (!res)
        z_process_message("Cannot connect to SZIG socket; socket='%s', reason='%s'", unaddr.sun_path, strerror(errnum));

      goto finish;
    }

  if (write(fd, request, strlen(request)) < 0)
    {
      z_process_message("Error sending request to SZIG socket; reason='%s'", strerror(errno));
      goto finish;
    }

  tv.tv_sec = deadlock_checker_timeout;
  tv.tv_usec = 0;
  FD_ZERO(&rdset);
  FD_SET(fd, &rdset);
  len = select(fd + 1, &rdset, NULL, NULL, &tv);
  switch (len)
    {
    case 0: /* ok, but no data available within the timeout */
      z_process_message("Timeout expired while waiting for SZIG response;");
      goto finish;

    case 1: /* ok, data is available for reading */
      break;

    case -1: /* error, reason comes in errno */
      z_process_message("Error waiting for SZIG response; reason='%s'", strerror(errno));
      goto finish;

    default: /* this just can't happen */
      g_assert_not_reached();
      break;
    }

  if ((len = read(fd, response, sizeof(response) - 1)) < 0)
    {
      int errnum = errno;
      res = z_is_deadlock_szig_error_ignored(COMM_PHASE_READ, errnum);
      if (!res)
        z_process_message("Error reading SZIG response; reason='%s'", strerror(errnum));

      goto finish;
    }

  response[len] = 0;
  if (response[len - 1] == '\n')
    response[len - 1] = 0;

  res = TRUE;

finish:
  if (fd >= 0)
    close(fd);

  return res;
}

#ifdef PREDICTABLE_RANDOM_ENABLED

// These don't need to do anything if you don't have anything for them to do.
static void stdlib_rand_cleanup() {}
static void stdlib_rand_add(const void *buf, int num, double add_entropy)
{
  (void) buf;
  (void) num;
  (void) add_entropy;
}
static int stdlib_rand_status() { return 1; }

// Seed the RNG.  srand() takes an unsigned int, so we just use the first
// sizeof(unsigned int) bytes in the buffer to seed the RNG.
static void stdlib_rand_seed(const void *buf, int num)
{
  assert(num >= (int)sizeof(unsigned int));
  srand(*((unsigned int *) buf));
}

// Fill the buffer with the same values, so the random function will return always the same.
// This is needed to replay the same connection multiple times.
static int stdlib_rand_bytes(unsigned char *buf, int num)
{
  for(int index = 0; index < num; ++index)
    {
      buf[index] = 10;
    }
  return 1;
}

// Create the table that will link OpenSSL's rand API to our functions.
RAND_METHOD stdlib_rand_meth = {
  stdlib_rand_seed,
  stdlib_rand_bytes,
  stdlib_rand_cleanup,
  stdlib_rand_add,
  stdlib_rand_bytes,
  stdlib_rand_status
};

// This is a public-scope accessor method for our table.
RAND_METHOD *RAND_stdlib() { return &stdlib_rand_meth; }

#endif

int
main(int argc, char *argv[])
{
  gchar log_progname[128];
  const gchar *pid_file = NULL;
  gchar pid_file_buf[128];
  GOptionContext *ctx;
  gboolean foreground = FALSE;
  GError *error = NULL;
  gboolean session_lic_initated = FALSE;

  z_mem_trace_init("zorp-memtrace.txt");
  instance_name = "zorp";
  instance_policy_list[0] = "zorp";
  virtual_instance_name = NULL;
  z_log_set_defaults(3, TRUE, TRUE, "*.summary:4,*.accounting:4");

  z_thread_set_max_threads(1000);       /* set our own default value for max_threads in ZThread */

  z_process_set_argv_space((gint) argc, (gchar **) argv);
  z_process_set_caps("cap_net_bind_service=p cap_net_admin,cap_net_raw=ip");

  ctx = g_option_context_new("zorp");
  z_libzorpll_add_option_groups(ctx, 0);
  g_option_context_add_main_entries(ctx, zorp_options, NULL);
  if (!g_option_context_parse(ctx, &argc, &argv, &error))
    {
      fprintf(stderr, "%s: %s", instance_name, error ? error->message : "Unknown error");
      exit(1);
    }
  g_option_context_free(ctx);

  if (argc > 1)
    {
      fprintf(stderr, "%s: Invalid arguments.\n", instance_name);
      return 1;
    }
  instance_policy_list[instance_count] = NULL;

  if (!virtual_instance_name)
    virtual_instance_name = static_cast<const gchar *>(g_strdup(instance_name));

  if (display_version)
    {
      z_version();
      exit(0);
    }

  if (!z_log_get_use_syslog())
    foreground = TRUE;

  if (pid_file == NULL)
    {
      g_snprintf(pid_file_buf, sizeof(pid_file_buf), "zorp-%s.pid", virtual_instance_name);
      pid_file = pid_file_buf;
    }

  /* NOTE: these do not override the values set by the user using command line arguments */
  z_process_set_pidfile_dir(ZORP_PID_FILE_DIR);
  z_process_set_working_dir(ZORP_WORKING_DIR);
  z_process_set_pidfile(pid_file);
  z_process_set_name(virtual_instance_name);
  z_process_set_use_fdlimit(TRUE);
  z_process_set_check(deadlock_checker_timeout, zorp_deadlock_checker);

  /* NOTE: the current user is root and there is no user/group specified,
   * then assume 'zorp'/'zorp' */
  if (getuid() == 0)
    {
      z_process_set_user("zorp");
      z_process_set_group("zorp");
    }

  if (foreground)
    z_process_set_mode(Z_PM_FOREGROUND);

  /* NOTE: if startup fails, z_process_start() prints an appropriate
   * error to stderr and exits the process */
  z_process_start();

  startup_id = time(NULL);

  /* NOTE: this is the daemon process, we have stderr on the first
   * invocation, e.g. when we are not restarted automatically, the user
   * probably sees messages printed to stderr. */

  z_thread_init();
  g_main_context_acquire(NULL);

  g_snprintf(log_progname, sizeof(log_progname), "zorp/%s", instance_name);

  /*NOLOG*/
  if (!z_log_init(log_progname, ZLF_THREAD | (log_escape ? ZLF_ESCAPE : 0)))
    {
      fprintf(stderr, "%s: Error initializing logging subsystem\n", instance_name);
      exit_code = 1;
      goto deinit_exit;
    }

  z_log_enable_tag_map_cache(z_logtag_lookup, TOTAL_KEYWORDS);

  /*LOG
    This message reports the current verbosity level of Zorp.
   */
  z_log(NULL, CORE_DEBUG, 0, "Starting up; verbose_level='%d', version='%s (%s)', startup_id='%d'",
        z_log_get_verbose_level(), BROCHURE_VERSION, VERSION, startup_id);

  z_dgram_init();
  z_tp_socket_init();
  z_ssl_init();
  z_szig_init(virtual_instance_name);

  z_main_loop_init();


#ifdef HAVE_LINUX_NETLINK_H
  z_ifmon_init();
  z_dispatch_init();
#endif
  z_registry_init();


  z_proxy_hash_init();

  /* only used for PORT allocation within a given range */
  srand(time(NULL) ^ getpid());

  if (!z_python_init())
    {
      /*LOG
	This message indicates that Zorp was unable to initialize the Python engine.
	It is likely that your installation is broken. Check your packages and there version number.
       */
      z_llog(CORE_ERROR, 0, "Error initializing Python policy engine;");
      fprintf(stderr, "%s: Error initializing Python policy engine\n", instance_name);
      exit_code = 1;
      goto deinit_exit;
    }

  z_setup_signals();

#ifdef PREDICTABLE_RANDOM_ENABLED
  RAND_set_rand_method(RAND_stdlib());
  unsigned int seed = 0x12345;
  RAND_seed(&seed, sizeof(seed));
#endif

  /*NOLOG*/
  z_main_loop(policy_file, instance_name, instance_policy_list, virtual_instance_name, zorp_process_master_mode);

 deinit_exit:

  /*NOLOG*/
  z_llog(CORE_INFO, 3, "Shutting down; version='%s (%s)'",
         BROCHURE_VERSION, VERSION);

  z_thread_destroy();
  if (session_lic_initated)
    {
      z_python_destroy();
      z_dispatch_destroy();
#ifdef HAVE_LINUX_NETLINK_H
      z_ifmon_destroy();
#endif
    }
  z_main_loop_destroy();
  z_ssl_destroy();
  z_log_destroy();
  z_proxy_hash_destroy();
  z_mem_trace_dump();
#ifdef USE_DMALLOC
  dmalloc_shutdown();
  /* avoid second dump of dmalloc */
  rename("logfile", "logfile.dm");
#endif

  if (exit_code != 0)
    z_process_startup_failed(exit_code, TRUE);
  z_process_finish();
  return exit_code;
}
