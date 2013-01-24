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

void os_daemon_post_fork()
{
#ifdef __sun
  // TODO: launch fresh contract
#endif
}

void os_session_post_auth(const char* username, uid_t uid)
{
  // FreeBSD, MacOS X
#if HAVE_SETLOGIN
  if (setlogin(username) < 0) perror("setlogin()");
#endif

  // AIX
#if HAVE_USRINFO
  size_t len = strlen(username);
  const char fmt[] = "LOGIN=%s\0LOGNAME=%s\0NAME=%s\0";
  len = sizeof(fmt)-6 + 3*len;
  char* buf = malloc(len);
  if (buf) {
    sprintf(buf, fmt, username, username, username);
    if (usrinfo(SETUINFO, buf, len) < 0) perror("usrinfo(SETUINFO)");
    free(buf);
  }
#endif
#if HAVE_SETPCRED
  if (setpcred(username, 0) < 0) perror("setpcred()");
#endif

  // Linux
#ifdef __linux
  // This is ultra-simplistic. Admins who really care about setting the
  // loginuid should use pam_loginuid, which is more sophisticated in its
  // handling and communication with auditd. We set it here though, because
  // it is after all a uid for our process that the kernel tracks, so it's
  // not optional.
  FILE* f = fopen("/proc/self/loginuid", "r+");
  if (f) {
    if (ftruncate(fileno(f), 0) < 0) perror("ftruncate(/proc/self/loginuid)");
    else fprintf(f, "%lu", (unsigned long)uid);
    fclose(f);
  } else {
    debug("No /proc/self/loginuid");
  }
#endif

  // Solaris, MacOS X, FreeBSD
#if HAVE_SETAUDIT_ADDR
  // TODO finish
  /*
  auditinfo_addr_t ai;
  ai.ai_auid = uid;
  ai.ai_asid = AU_ASSIGN_ASID;
  mask = au_user_mask...
  setaudit_addr
  */
#endif
}

