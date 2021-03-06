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

#ifndef OS_H__
#define OS_H__

#include <config.h>
#include <unistd.h>
struct passwd;

#if HAVE_LOGIN_CAP
#include <sys/types.h>
#include <login_cap.h>
#endif

void os_daemon_post_fork();
void os_session_post_auth(char* username, uid_t uid);
int os_session_post_session(struct passwd* pw
#if HAVE_LOGIN_CAP
    , login_cap_t* login_class
#endif
);

#endif
