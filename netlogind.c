/*
  Copyright (c) 2013 Nicholas Wilson

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
 */

#include "config.h"
#include "util.h"
#include "net.h"
#include "session.h"
#include "os.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>
#include <termios.h>

#define SOCK_NAME "/tmp/netlogind.sock"
#if HAVE_CHROOT
#define CHROOT_DIR "/var/empty"
#endif


static int client_fd = -1;
static void client_fd_cleanup()
{
  if (client_fd < 0) return;
  if (close(client_fd) < 0) perror("close(client_fd)");
}

static int client_main();
static void client_cleanup()
{
  client_fd_cleanup();
}
static void client_fatal(const char* fmt, ...)
{
  client_cleanup();
  va_list ap;
  va_start(ap, fmt);
  vfatal(fmt, ap);
}

static char* daemon_username = 0;
static void daemonize();
static void daemon_cleanup()
{
  client_fd_cleanup();
  session_cleanup();
  free(daemon_username);
}
static void daemon_fatal(const char* fmt, ...)
{
  daemon_cleanup();
  va_list ap;
  va_start(ap, fmt);
  vfatal(fmt, ap);
}
static void auth_timeout(int sig)
{ if (sig == SIGALRM) daemon_fatal("Authentication timeout"); }

/*
 * This daemon provides sample code for how to start a process from a daemon,
 * as a logged-in user.
 *
 * The protocol is basic. This is intended as an example of the correct steps
 * to follow, and does not constitute a usable application. Run a proper
 * application, like VNC or SSH, if you actually want to log into a machine
 * remotely.
 *
 * Nonetheless, it does work!
 *
 * Usage: netlogind            - spawn a daemon that listens
 *        netlogind -client    - connect
 */

int main(int argc, char** argv) {
  int rv, client = 0, i;
  for (i = 0; i < argc; ++i) {
    if (!strcmp(argv[i], "-client")) client = 1;
    if (!strcmp(argv[i], "-debug")) debug_ = 1;
    if (!strcmp(argv[i], "-noauth")) perform_authentication = 0;
  }

  signal(SIGPIPE, SIG_IGN);

  if (client) return client_main();

  if (getuid() != 0 || geteuid() != 0)
    fatal("Daemon must run as root");

  if (is_un_connectable(SOCK_NAME))
    fatal("Daemon already running");

  if (!debug_) daemonize();

  (void)unlink(SOCK_NAME);
  int listen_fd = un_listen(SOCK_NAME);
  if (listen_fd < 0) fatal("Could not listen");

  while (1) {
    client_fd = accept(listen_fd, 0, 0);
    if (client_fd < 0 && errno == EINTR) continue;
    if (client_fd < 0) perror_fatal("accept()");
    if (debug_) break;
    fflush(0);
    rv = fork();
    if (rv < 0) perror_fatal("fork()");
    if (rv == 0) break;
    /* parent: reap child and accept again */
    int child = rv;
    while (1) {
      if (waitpid(child, 0, 0) < 0) {
        if (errno != EINTR) perror_fatal("waitpid()");
      } else break;
    }
    sleep(1); /* prevent fork-bomb */
  }
  if (!debug_) {
    /* This setsid() is important: the child is not in the same session as the
     * listener parent because we do actually call functions that affect the
     * whole session before forking again. */
    if (setsid() < 0) perror_fatal("setsid(listener_child)");
    os_daemon_post_fork();
    rv = fork();
    if (rv < 0) perror_fatal("fork()");
    if (rv > 0) _exit(0);
  }

  /* child: a process spawned for each client connection */
  setproctitle("[authenticating]");
  debug("Client connected");
  if (close(listen_fd) < 0) perror("close(listen_fd)");

  fflush(0);
  {
    int fd[2];
    if (socketpair(PF_UNIX, SOCK_STREAM, 0, fd) < 0)
      perror_fatal("socketpair()");
    rv = fork();
    if (rv < 0) fatal("fork()");
    if (rv == 0) {
      session_fd = fd[0];
      (void)close(fd[1]);
      (void)close(client_fd);
    } else {
      session_fd = fd[1];
      (void)close(fd[0]);
    }
  }
  if (rv == 0) return session_main();
  session_pid = rv;

  /* If we need root or user privileges later, we could use privilege separation
   * here, and drop root after authentication. */

  struct passwd pw, *pwp;
  char pw_buf[1024];
  rv = getpwnam_r("nobody", &pw, pw_buf, sizeof(pw_buf), &pwp);
  if (!pwp) {
    if (rv) { errno = rv; perror("getpwnam()"); }
    debug("Warning: not dropping privileges");
  } else {
#if HAVE_CHROOT
    if (chroot(CHROOT_DIR) < 0) perror("chroot("CHROOT_DIR")");
#endif
    setpasswd(pwp);
  }

  /* Set the auth timeout alarm; this and the sleep(1) above guarantee that
   * max load on the system from unauthenticated users is 60 processes. */
  signal(SIGALRM, auth_timeout);
  alarm(5);

  /* Main loop: session-driven */
  int authenticated = 0;
  while(1) {
    int msg = read_msg_type(session_fd);
    switch(msg) {
    case MSG_FINISH:
      {
        int status = read_uint(session_fd);
        if (status < 0) daemon_fatal("Unexpected disconnection");
        if (authenticated || status) {
          if (authenticated ||
              write_text(client_fd, "Authentication failed\n") >=0)
            (void)write_finish(client_fd, status);
        }
        if (status) authenticated = 1;
        if (!authenticated) {
          daemon_username = read_reply(session_fd);
          if (!daemon_username)
            daemon_fatal("Unexpected disconnection");
        }
        break;
      }
    case MSG_TEXT:
      {
        char* text = read_str(session_fd);
        if (!text) daemon_fatal("Unexpected disconnection");
        rv = write_text(client_fd, text);
        free(text);
        if (rv < 0) daemon_fatal("Unexpected disconnection");
      }
      break;
    case MSG_PROMPT:
      {
        int echo = read_uint(session_fd);
        if (echo < 0) daemon_fatal("Unexpected disconnection");
        if (write_prompt(client_fd, echo) < 0)
          daemon_fatal("Unexpected disconnection");
        char* reply = read_reply(client_fd);
        if (!reply) daemon_fatal("Unexpected disconnection");
        rv = write_reply(session_fd, reply);
        buffer_scrub(reply, strlen(reply));
        free(reply);
        if (rv < 0) daemon_fatal("Unexpected disconnection");
      }
      break;
    default:
      daemon_fatal("Bad message id %d", msg);
      break;
    }
    if (msg == MSG_FINISH) {
      if (authenticated) break;
      authenticated = 1;

      /* At this point, if we were doing the privsep design, we'd rejoin the
       * [net] process, perform whatever action we were interested in staying
       * root for, then drop our privileges. */
      alarm(0);
      setproctitle("%s [net]", daemon_username);
      debug("Session process running for \"%s\"", daemon_username);
    }
  }

  (void)write_finish(client_fd, 0);
  daemon_cleanup();

  return 0;
}

/*
 * Protocol:
 *   Server to client:
 *     int MSG_FINISH int error
 *     int MSG_TEXT str text
 *     int MSG_PROMPT int echo
 *   Client to server:
 *     int MSG_REPLY str text
 */
int client_main()
{
  client_fd = un_connect(SOCK_NAME);
  if (client_fd < 0) fatal("Failed to connect to server");
 
  while(1) {
    int msg = read_msg_type(client_fd);
    switch(msg) {
    case MSG_FINISH:
      {
        int status = read_uint(client_fd);
        if (status < 0) client_fatal("Unexpected disconnection");
        return status ? 1 : 0;
      }
    case MSG_TEXT:
      {
        char* text = read_str(client_fd);
        if (!text) client_fatal("Unexpected disconnection");
        printf("%s", text);
        fflush(stdout);
        free(text);
      }
      break;
    case MSG_PROMPT:
      {
        int echo = read_uint(client_fd);
        if (echo < 0) client_fatal("Unexpected disconnection");
        struct termios attrs;
        tcgetattr(fileno(stdin), &attrs);
        tcflag_t orig = attrs.c_lflag;
        if (!echo) attrs.c_lflag &= ~ECHO & ~ECHONL;
        tcsetattr(fileno(stdin), TCSAFLUSH, &attrs);
        attrs.c_lflag = orig;
        char buf[1024];
        char* str = fgets(buf, sizeof(buf), stdin);
        tcsetattr(fileno(stdin), TCSAFLUSH, &attrs);
        if (!echo) fputc('\n', stdout);
        if (!str && ferror(stdin)) fatal("User input read error");
        if (!str) str = "";
        size_t len = strlen(str);
        if (len && str[len-1] != '\n') {
          fprintf(stderr, "User input too long: truncating\n");
          while(1) {
            char buf[1024];
            char* discard = fgets(buf, sizeof(buf), stdin);
            if (!discard && ferror(stdin)) fatal("User input read error");
            if (!discard) break;
            if (discard[strlen(discard)-1] == '\n') break;
          }
        }
        if (len) str[len-1] = '\0';
        if (write_reply(client_fd, str) < 0)
          client_fatal("Unexpected disconnection");
        buffer_scrub(buf, sizeof(buf));
      }
      break;
    default:
      client_fatal("Bad message id %d", msg);
      break;
    }
  }
  client_cleanup();
  return 0;
}

void daemonize()
{
  chdir("/");
  umask(077);
  int err = fork();
  if (err < 0) perror_fatal("daemonize:fork()");
  if (err > 0) _exit(0);
  if (setsid() < 0) perror_fatal("daemonize:setsid()");
  err = fork();
  if (err < 0) perror_fatal("daemonize:fork2()");
  if (err > 0) _exit(0);
}
