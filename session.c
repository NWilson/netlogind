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

#include <config.h>
#include "session.h"
#include "util.h"
#include "net.h"
#include "os.h"
#include "pam.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
extern char** environ;

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>

pid_t session_pid = -1; 
int session_fd = -1;
static char* username = 0;
static struct passwd pw;

#if !HAVE_PAM
int perform_authentication = 0;
#else
int perform_authentication = 1;
#define PAM_APPL_NAME "netlogind"
#endif

void session_cleanup()
{
  int err, status;
  free(username); username = 0;

  if (session_fd >= 0 && close(session_fd) < 0) perror("close(session_fd)");
  session_fd = -1;

#if HAVE_PAM
  pam_cleanup();
#endif

  if (session_pid < 0) return;
  while ((err = waitpid(session_pid, &status, WNOHANG)) < 0 && errno == EINTR)
    ;
  if (err < 0) perror("waitpid(session_pid)");
  else if (err == 0) debug("Abandoned session child");
  else if (WIFEXITED(status) && WEXITSTATUS(status))
    fprintf(stderr, "Session child exited abnormally: code %d\n",
                    WEXITSTATUS(status));
  else if (WIFSIGNALED(status))
    psignal(WTERMSIG(status), "Session child termined");
  session_pid = (pid_t)-1;
}

static void session_fatal(const char* fmt, ...)
{
  session_cleanup();
  if (!fmt) exit(1);
  va_list ap;
  va_start(ap, fmt);
  vfatal(fmt, ap);
}

static void session_environ()
{
  char* path = strdup(getenv("PATH"));
  *environ = 0;
  setenv("HOME",pw.pw_dir,1);
  setenv("USER",pw.pw_name,1);
  setenv("LOGNAME",pw.pw_name,1);
  setenv("LOGIN",pw.pw_name,1); // Only strictly required on AIX
  setenv("PATH",path,1);
  free(path);
#if HAVE_PAM
  pam_export_environ();
#endif
}

/* The protocol the main thread uses to talk to the session is
 * simple: TEXT is sent to the client, PROMPT is sent to the
 * client and REPLY sent back. The first FINISH marks the end of
 * authentication, at which point we send over the username in a
 * TEXT message. If the status is 0, we enter the command loop
 * and again relay prompts to the client in the main thread. */
int session_main()
{
  int rv;
  //freopen("/dev/null", "w+", stderr);
  setproctitle("[session]");
  if (write_text(session_fd, "Username: ") < 0 ||
      write_prompt(session_fd, 1) < 0)
    session_fatal("Unexpected disconnection");
  username = read_reply(session_fd);
  if (!username) session_fatal("No username returned");

#if !HAVE_PAM
  perform_authentication = 0;
#endif
  if (!perform_authentication) {
    if (write_text(session_fd, "Skipping authentication\n") < 0)
      session_fatal("Unexpected disconnection");
  }
#if HAVE_PAM
  else {
    if (pam_authenticate_session(&username, session_fd) < 0) {
      (void)write_finish(session_fd, 1);
      session_fatal("Authentication failed");
    }
  }
#endif

  struct passwd* pwp;
  char pw_buf[1024];
  rv = getpwnam_r(username, &pw, pw_buf, sizeof(pw_buf), &pwp);
  if (!pwp) {
    (void)write_finish(session_fd, 1);
    if (rv) { errno = rv; perror("getpwnam()"); }
    session_fatal(rv ? "Fetching username failed" :
                       "No matching passwd entry");
  }

  /* XXX username was untrusted client input: reject it if it
   *     doesn't match its strvis */

  os_session_post_auth(username, pw.pw_uid);

  if (setgid(pw.pw_gid) < 0 || getgid() != pw.pw_gid || getegid() != pw.pw_gid)
    fatal("Could not setgid");
  /* We must call initgroups() before pam_start_session(), otherwise we would
   * trample on any groups added through PAM. */
  if (initgroups(pw.pw_name, pw.pw_gid) < 0) perror_fatal("initgroups()");

#if HAVE_PAM
  if (pam_begin_session(username) < 0) {
    (void)write_finish(session_fd, 1);
    session_fatal("PAM session creation failed");
  }
#endif

  setproctitle("%s [session]", username);
  if (write_finish(session_fd, 0) < 0 ||
      write_reply(session_fd, username) < 0)
    session_fatal("Unexpected disconnection");

  /* We guard every fork() below with setreuid so the user's resource limits
   * are correctly applied. */
  if (setreuid(pw.pw_uid, -1) < 0) perror("setreuid(pw_uid)");
  while(1) {
    while(1) {
      rv = waitpid(-1, 0, WNOHANG);
      if (rv == 0 || (rv < 0 && errno == ECHILD)) break;
      if (rv < 0) {
        perror("waitpid()");
        (void)write_finish(session_fd, 1);
        session_fatal(0);
      }
    }
    if (write_text(session_fd, "Command: ") < 0)
      session_fatal("Unexpected disconnection");
    if (write_prompt(session_fd, 1) < 0)
      session_fatal("Unexpected disconnection");
    char* command = read_reply(session_fd);
    if (!command) session_fatal("Unexpected disconnection");
    if (!command[0]) break;
    /* XXX do strvis(command) */
    debug("Running command \"%s\"", command);
    fflush(0);
    int err = fork();
    if (err < 0) {
      perror("fork()");
      (void)write_finish(session_fd, 1);
      session_fatal(0);
    }
    if (err) { free(command); continue; }

    (void)close(session_fd);
    closefrom(3);
    signal(SIGPIPE, SIG_DFL);

    if (setreuid(0, -1) < 0) perror("setreuid(root)");
    if (setuid(pw.pw_uid) < 0 || getuid() != pw.pw_uid || geteuid() != pw.pw_uid)
      fatal("Could not setuid");

    session_environ();

    execlp(command, command, (char*)0);
    perror("execlp()");
    _exit(1);
  }
  if (setreuid(0, -1) < 0) perror("setreuid(root)");

  (void)write_finish(session_fd, 0);

  while(1) {
    rv = wait(0);
    if (rv < 0 && errno == ECHILD) break;
    if (rv < 0) perror_fatal("waitpid()");
  }

  session_cleanup();
  return 0;
}

