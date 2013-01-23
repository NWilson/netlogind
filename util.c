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
    perror_fatal("user id change failed");
  }

  if (getuid() != pwp->pw_uid || geteuid() != pwp->pw_uid ||
      getgid() != pwp->pw_gid || getegid() != pwp->pw_gid)
  {
    fatal("uid/gid not correctly set!");
  }
}

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
void setproctitle(const char* fmt, ...) { }
#endif

