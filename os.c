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
#include "os.h"
#include "util.h"

#if HAVE_BSM_AUDIT_H
#include <unistd.h>
#include <bsm/audit.h>
#endif
#if HAVE_BSM_LIBBSM_H
#include <bsm/libbsm.h>
#endif

#if HAVE_USRINFO
#include <uinfo.h>
#endif
#if HAVE_SETPCRED
#include <usersec.h>
#endif

#if HAVE_LIBPROJECT
#include <project.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

void os_daemon_post_fork()
{
#ifdef __sun
  /* TODO: launch fresh contract */
#endif
}

void os_session_post_auth(char* username, uid_t uid)
{
  /* FreeBSD, MacOS X */
#if HAVE_SETLOGIN
  if (setlogin(username) < 0) perror_fatal("setlogin()");
#endif

  /* AIX */
#if HAVE_USRINFO
  size_t len = strlen(username);
  const char fmt[] = "LOGIN=%s\0LOGNAME=%s\0NAME=%s\0";
  len = sizeof(fmt)-6 + 3*len;
  char* buf = malloc(len);
  if (buf) {
    sprintf(buf, fmt, username, username, username);
    if (usrinfo(SETUINFO, buf, len) < 0) perror_fatal("usrinfo(SETUINFO)");
    free(buf);
  } else fatal("malloc()");
#endif
#if HAVE_SETPCRED
  const char* override[] = { "REAL_USER=root", 0 };
  if (setpcred(username, override) < 0) perror_fatal("setpcred()");
#endif

  /* Linux */
#ifdef __linux
  /* This is ultra-simplistic. Admins who really care about setting the loginuid
   * should use pam_loginuid, which is more sophisticated in its handling and
   * communication with auditd. We have to set it here though, because it's our
   * responsibility to try to correctly set every user-id the kernel has. */
  FILE* f = fopen("/proc/self/loginuid", "r+");
  if (f) {
    if (ftruncate(fileno(f), 0) < 0)
      perror_fatal("ftruncate(/proc/self/loginuid)");
    else if (fprintf(f, "%lu", (unsigned long)uid) < 0 || fclose(f) != 0)
      perror_fatal("fflush(/proc/self/loginuid)");
  } else {
    debug("No /proc/self/loginuid; skip setting audituid");
  }
#endif

  /* Solaris, MacOS X, FreeBSD */
#if HAVE_BSM_AUDIT_H
  auditinfo_addr_t ai = {0,};
  int audit_enabled = 1;

  /* Solaris BSM doesn't have ai_flags, but OpenBSM does. We are just making
   * sure that if there are fields in the ai structure we don't know about, we
   * leave them at their current value. */
  if (getaudit_addr(&ai, sizeof(ai)) < 0) {
    auditinfo_addr_t null = {0,};
    ai = null;
#ifdef __sun
    if (errno == EINVAL)
#else
    if (errno == ENOSYS)
#endif
    {
      debug("Skip setting audit-uid (auditing disabled for system)");
      audit_enabled = 0;
    } else perror("getaudit_addr()");
  }
  ai.ai_auid = uid;
#ifdef AU_ASSIGN_ASID
  ai.ai_asid = AU_ASSIGN_ASID;
#else
  ai.ai_asid = getsid(0);
#endif

  /* This API is rubbish. It assumes a session represents a connection from one
   * location; what if two users are cooperating? Stupid API. Don't use this
   * field for anything unless you're telnet or similar. */
  au_tid_addr_t termid = {0,};
  ai.ai_termid = termid;
  ai.ai_termid.at_type = AU_IPv4;

  if (!audit_enabled) {
    /* */
  } if (au_user_mask(username, &ai.ai_mask) < 0) {
    au_mask_t null = {0,};
    ai.ai_mask = null;
    perror("au_user_mask()"); /* Should this be fatal? */
  } else if (setaudit_addr(&ai, sizeof(ai)) < 0)
    perror_fatal("setaudit_addr()");
#endif

}

int os_session_post_session(char* username)
{
#ifdef __linux
  /* TODO If it wasn't done through PAM, we should double-check that the
   *      SELinux execution context we're about to use is right. */
#endif

  /* Solaris 10 */
#if HAVE_LIBPROJECT
  char pbuf[5*1024], cbuf[sizeof(pbuf)];
  projid_t pid = getprojid();
  if (pid < 0) perror_fatal("getprojid()");
  struct project proj, *pproj = getprojbyid(pid, &proj, cbuf, sizeof(cbuf));
  if (!pproj) {
    perror("Current project not in database. getprojbyid()");
    return -1;
  }
  if (!inproj(username, proj.pj_name, pbuf, sizeof(pbuf))) {
    fprintf(stderr, "User is not in the current project.\n");
    return -1;
  }
#endif

  return 0;
}
