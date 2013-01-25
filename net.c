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

#include "net.h"
#include "util.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>

/* An int has the right width on every modern platform. */
typedef unsigned int uint32_net;
typedef char static_assert1[sizeof(uint32_net)*2 - 7];
typedef char static_assert2[9 - sizeof(uint32_net)*2];

int is_un_connectable(const char* sock)
{
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) perror_fatal("is_un_connectable:socket()");
  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  assert(strlcpy(addr.sun_path, sock, sizeof(addr.sun_path)) <
           sizeof(addr.sun_path));
  int err = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
  close(fd);
  if (err < 0) {
    if (errno == ECONNREFUSED || errno == EDESTADDRREQ || errno == ENOENT)
      return 0;
    perror_fatal("is_un_connectable:connect()");
  }
  return 1;
}

int un_listen(const char* sock)
{
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) perror_fatal("un_listen:socket()");
  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  assert(strlcpy(addr.sun_path, sock, sizeof(addr.sun_path)) <
           sizeof(addr.sun_path));
  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
  { close(fd); perror("un_listen:bind()"); return -1; }
  if (listen(fd, 5) < 0)
  { close(fd); perror("un_listen:listen()"); return -1; }
  if (chmod(sock, 0666) < 0)
  { close(fd); perror("un_listen:chmod()"); return -1; }
  return fd;
}

int un_connect(const char* sock)
{
  struct sockaddr_un addr;
  int rv, fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) perror_fatal("un_connect:socket()");
  addr.sun_family = AF_UNIX;
  assert(strlcpy(addr.sun_path, sock, sizeof(addr.sun_path)) <
           sizeof(addr.sun_path));
  rv = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
  if (rv < 0) { perror("un_connect:connect()"); close(fd); return -1; }
  return fd;
}

static int readbuf_(int fd, void* buf_, int len)
{
  char* buf = (char*)buf_;
  while(len) {
    int err = read(fd, buf, len);
    if (err < 0 && errno == EINTR) continue;
    if (err < 0) { perror("read()"); return -1; }
    if (err == 0) { break; }
    len -= err;
    buf += err;
  }
  if (len) {
    fprintf(stderr, "incomplete readbuf()\n");
    return -1;
  }
  return 0;
}

static int writebuf_(int fd, const void* buf_, int len)
{
  const char* buf = (const char*)buf_;
  while(len) {
    int err = write(fd, buf, len);
    if (err < 0 && errno == EINTR) continue;
    if (err < 0) { perror("write()"); return -1; }
    len -= err;
    buf += err;
  }
  return 0;
}

int write_finish(int fd, int status)
{
  if (write_uint(fd, MSG_FINISH) < 0) return -1;
  return write_uint(fd, status);
}
int write_text(int fd, const char* str)
{
  if (write_uint(fd, MSG_TEXT) < 0) return -1;
  return write_str(fd, str);
}
int write_prompt(int fd, int echo)
{
  if (write_uint(fd, MSG_PROMPT) < 0) return -1;
  return write_uint(fd, echo);
}
int write_reply(int fd, const char* str)
{
  if (write_uint(fd, MSG_REPLY) < 0) return -1;
  return write_str(fd, str);
}
int write_str(int fd, const char* str)
{
  size_t len = strlen(str);
  if (len > INT_MAX) len = INT_MAX;
  if (write_uint(fd, (int)len) < 0) return -1;
  return writebuf_(fd, str, (int)len);
}
int write_uint(int fd, int i_)
{
  uint32_net i = (uint32_net)i_;
  assert(i_ >= 0);
  return writebuf_(fd, &i, sizeof(i));
}
int read_msg_type(int fd) { return read_uint(fd); }
char* read_reply(int fd)
{
  if (read_uint(fd) != MSG_REPLY) return 0;
  return read_str(fd);
}
char* read_str(int fd)
{
  int len = read_uint(fd);
  if (len < 0) return 0;
  char* buf = malloc(len+1);
  if (!buf) { fatal("malloc()"); assert(0); }
  buf[len] = '\0';
  if (readbuf_(fd, buf, len) < 0) { free(buf); return 0; }
  return buf;
}
int read_uint(int fd)
{
  uint32_net i;
  if (readbuf_(fd, &i, sizeof(i)) < 0) return -1;
  if (i > INT_MAX) return -1;
  return (int)i;
}
