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

#include "util.h"

#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>

#if HAVE_PSTAT_GETPROC
#include <sys/param.h>
#include <sys/pstat.h>
#endif

int debug_ = 0;

void debug(const char* str, ...)
{
  if (!debug_) return;
  va_list ap;
  va_start(ap, str);
  vfprintf(stderr, str, ap);
  va_end(ap);
  fputc('\n', stderr);
}

void fatal(const char* str, ...)
{
  va_list ap;
  va_start(ap, str);
  vfatal(str, ap);
}

void vfatal(const char* str, va_list ap)
{
  vfprintf(stderr, str, ap);
  fputc('\n', stderr);
  exit(1);
}

void perror_fatal(const char* str)
{
  perror(str);
  exit(1);
}

void setpasswd(struct passwd* pwp)
{
  if (setgid(pwp->pw_gid) < 0 ||
      initgroups(pwp->pw_name, pwp->pw_gid) ||
      setuid(pwp->pw_uid) < 0)
  {
    debug("Attempted to switch to user %s(%d)", pwp->pw_name, pwp->pw_uid);
    perror_fatal("user id change failed");
  }

  if (getuid() != pwp->pw_uid || geteuid() != pwp->pw_uid ||
      getgid() != pwp->pw_gid || getegid() != pwp->pw_gid)
  {
    fatal("uid/gid not correctly set!");
  }
}

void buffer_scrub(void* buf_, size_t len)
{
  volatile char* buf = buf_;
  while (len--) *buf++ = '\0';
}

#if !HAVE_PSIGNAL
void psignal(int sig, const char *s)
{
  if (s && s[0]) fprintf(stderr, "%s: ", s);
  fprintf(stderr, "%d\n", sig);
}
#endif

#if !HAVE_STRLCPY
size_t
strlcpy(char * /*restrict*/ dst, const char * /*restrict*/ src,
        size_t size)
{
  size_t len = strlen(src), cp_len = len > size-1 ? size-1 : len;
  memcpy(dst, src, cp_len);
  dst[cp_len] = '\0';
  return len;
}
#endif

#if !HAVE_SETENV
int setenv(const char *name, const char *value, int overwrite)
{
  if (getenv(name) && !overwrite) return 0;
  size_t len = strlen(name) + strlen(value) + 2;
  char* str = malloc(len);
  if (!str) { errno = ENOMEM; return -1; }
  assert(sprintf(str, "%s=%s", name, value) == len-1);
  return putenv(str) ? -1 : 0;
}
#endif

#if !HAVE_SETPROCTITLE
/* No point emulating; it's just cosmetic */
void setproctitle(const char* fmt, ...) { }
#endif

#if !HAVE_SETREUID
int setreuid(uid_t ruid, uid_t euid)
{
#if HAVE_SETRESUID
  return setresuid(ruid, euid, -1);
#else
  errno = ENOTSUP;
  return;
#endif
}
#endif

#if !HAVE_CLOSEFROM
/* see http://stackoverflow.com/questions/899038/ */
void closefrom(int lowfd)
{
#ifdef F_CLOSEM
  /* AIX */
  (void)fcntl(lowfd, FCLOSEM, 0);

#elif HAVE_PSTAT_GETPROC
  /* HP-UX */
  struct pst_status ps;
  if (pstat_getproc(&ps, sizeof(ps), (size_t)0, (int)getpid()) < 0)
    perror("pstat_getproc()");
  int i = lowfd;
  for (; i <= ps.pst_highestfd; ++i) (void)close(i);
#else

  /* TODO total blinking pain... */

#endif
}
#endif

