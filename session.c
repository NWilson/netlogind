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

#include "session.h"
#include "util.h"

#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>

pid_t session_pid = -1; 

void session_cleanup()
{
  int err, status;
  if (session_pid < 0) return;
  while ((err = waitpid(session_pid, &status, WNOHANG)) < 0 && errno == EINTR) ;
  if (err < 0) perror("waitpid(session_pid)");
  else if (err == 0) debug("Abandoned session child");
  else if (WIFEXITED(status) && WEXITSTATUS(status))
    fprintf(stderr, "Session child exited abnormally: code %d\n",
                    WEXITSTATUS(status));
  else if (WIFSIGNALED(status))
    psignal(WTERMSIG(status), "Session child termined");
}

