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

#ifndef UTIL_H__
#define UTIL_H__

#include <config.h>
#include <string.h>
#include <stdarg.h>

extern int debug_;
void debug(const char* str, ...);
void fatal(const char* str, ...);
void vfatal(const char* str, va_list ap);
void perror_fatal(const char* str);

#if !HAVE_STRLCPY
size_t strlcpy(char * /*restrict*/ dst, const char * /*restrict*/ src,
               size_t size);
#endif

#if !HAVE_SETENV
int setenv(const char *name, const char *value, int overwrite);
#endif

#if !HAVE_SETPROCTITLE
void setproctitle(const char *fmt, ...);
#endif

#endif
