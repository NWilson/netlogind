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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
extern char** environ;

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <termios.h>

int debug;
int client_main();
void fatal(const char* str, ...);
void perror_fatal(const char* str);
void daemonize();
int is_un_connectable(const char* sock);
int un_listen(const char* sock);
#define SOCK_NAME "/tmp/netlogind.sock"
#define MSG_FINISH 1
#define MSG_TEXT 2
#define MSG_PROMPT 3
#define MSG_REPLY 4

int client_fd;
void write_finish(int status); /* calls exit(1) if status>0 */
void write_text(char* str);
void write_prompt(int echo);
void write_reply(char* str);
void write_str(char* str);
void write_int(int i);
int read_msg_type();
char* read_reply();
char* read_str();
int read_int();

/*
 * This is a brain-dead simple example of how to start a process from a
 * daemon, as a logged-in user.
 *
 * The protocol is basic. This is intended as an example of the correct
 * steps to follow, and does not constitute a usable application. Run a
 * proper product, like VNC, if you actually want to log into a machine
 * remotely.
 *
 * It functions, for the purpose of inspecting its workings.
 *
 * Usage: netlogind            - spawn a daemon that listens
 *        netlogind -client    - connect!
 */

int main(int argc, char** argv) {
  int client = argc > 1 && !strcmp(argv[1], "-client");
  debug = argc > 1 && !strcmp(argv[1], "-debug");
  int err;

  if (client) return client_main();

  if (getuid() != 0 || geteuid() != 0)
    fatal("Daemon must run as root");

  if (is_un_connectable(SOCK_NAME))
    fatal("Daemon already running");

  if (!debug) daemonize();
  signal(SIGPIPE, SIG_IGN);

  unlink(SOCK_NAME);
  int listen_fd = un_listen(SOCK_NAME);
  if (listen_fd < 0) fatal("Could not listen");

  while (1) {
    client_fd = accept(listen_fd, 0, 0);
    if (client_fd < 0 && errno == EINTR) continue;
    if (client_fd < 0) perror_fatal("accept()");
    if (debug) break;
    err = fork();
    if (err < 0) perror_fatal("fork()");
    if (err == 0) break;
    /* parent: reap child and accept again */
    int child = err;
    while (1) {
      if (waitpid(child, 0, 0) < 0) {
        if (errno != EINTR) perror_fatal("waitpid()");
        else continue;
      }
      break;
    }
  }
  if (!debug) {
    setsid();
    err = fork();
    if (err < 0) perror_fatal("fork()");
    if (err > 0) _exit(0);
  }

  /* child: a process spawned for each client connection */
  close(listen_fd);

  write_text("Username: ");
  write_prompt(1);
  char* username = read_reply();
  struct passwd pw, *pwp;
  char pw_buf[1024];
  err = getpwnam_r(username, &pw, pw_buf, sizeof(pw_buf), &pwp);
  free(username);
  if (!pwp) {
    if (!err) fprintf(stderr, "No matching passwd entry");
    else { errno = err; perror("getpwnam"); }
    write_finish(1);
  }

  if (setgid(pw.pw_gid) < 0) {
    perror("setgid()");
    write_finish(1);
  }
  if (initgroups(pw.pw_name, pw.pw_gid) < 0) {
    perror("initgroups()");
    write_finish(1);
  }
  if (setuid(pw.pw_uid) < 0) {
    perror("setuid()");
    write_finish(1);
  }

  if (getuid() != pw.pw_uid || geteuid() != pw.pw_uid ||
      getgid() != pw.pw_gid || getegid() != pw.pw_gid) {
    fprintf(stderr, "uid/gid not correctly set!");
    write_finish(1);
  }

  char* path = strdup(getenv("PATH"));
  *environ = 0;
  setenv("HOME",pw.pw_dir,1);
  setenv("USER",pw.pw_name,1);
  setenv("PATH",path,1);
  free(path);

  while(1) {
    while(1) {
      err = waitpid(-1, 0, WNOHANG);
      if (err == 0 || (err < 0 && errno == ECHILD)) break;
      if (err < 0) { perror("waitpid()"); write_finish(1); }
    }
    write_text("Command: ");
    write_prompt(1);
    char* command = read_reply();
    if (!command[0]) break;
    printf("Running command \"%s\"\n", command);
    int err = fork();
    if (err < 0) { perror("fork()"); write_finish(1); }
    if (err) { free(command); continue; }
    close(client_fd);
    execlp(command, command, (char*)0);
    perror("execlp()");
  }

  write_finish(0);
  close(client_fd);

  while(1) {
    err = wait(0);
    if (err < 0 && errno == ECHILD) break;
    if (err < 0) perror_fatal("waitpid()");
  }
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
  client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (client_fd < 0) perror_fatal("socket()");
  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  assert(strlcpy(addr.sun_path, SOCK_NAME, sizeof(addr.sun_path)) <
           sizeof(addr.sun_path));
  if (connect(client_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    perror_fatal("connect()");
 
  while(1) {
    int msg = read_msg_type();
    switch(msg) {
    case MSG_FINISH:
      return read_int() ? 1 : 0;
    case MSG_TEXT:
      {
        char* text = read_str();
        printf("%s", text);
        fflush(stdout);
        free(text);
      }
      break;
    case MSG_PROMPT:
      {
        int echo = read_int();
        struct termios attrs;
        tcgetattr(fileno(stdin), &attrs);
        tcflag_t orig = attrs.c_lflag;
        if (!echo) attrs.c_lflag &= ~ECHO & ~ECHONL;
        tcsetattr(fileno(stdin), TCSAFLUSH, &attrs);
        attrs.c_lflag = orig;
        char buf[1024];
        char* str = fgets(buf, sizeof(buf), stdin);
        tcsetattr(fileno(stdin), TCSAFLUSH, &attrs);
        if (!str && ferror(stdin)) fatal("User input read error");
        if (!str) str = "\n";
        size_t len = strlen(str);
        if (str[len-1] != '\n') fatal("User input too long");
        str[len-1] = '\0';
        write_reply(str);
      }
      break;
    default:
      fatal("bad message id %d");
      break;
    }
  }
  return 0;
}

void fatal(const char* str, ...)
{
  va_list ap;
  va_start(ap, str);
  vfprintf(stderr, str, ap);
  va_end(ap);
  fputc('\n', stderr);
  exit(1);
}

void perror_fatal(const char* str)
{
  perror(str);
  exit(1);
}

void daemonize()
{
  chdir("/");
  umask(077);
  int err = fork();
  if (err < 0) perror_fatal("daemonize:fork()");
  if (err > 0) _exit(0);
  setsid();
  err = fork();
  if (err < 0) perror_fatal("daemonize:fork2()");
  if (err > 0) _exit(0);
}

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

void readbuf_(void* buf_, int len)
{
  char* buf = (char*)buf_;
  while(len) {
    int err = read(client_fd, buf, len); 
    if (err < 0 && errno == EINTR) continue;
    if (err < 0) perror_fatal("read()");
    if (err == 0) { printf("EOF\n"); break; }
    len -= err;
    buf += err;
  }
  if (len) fatal("incomplete read()");
}

void writebuf_(void* buf_, int len)
{
  char* buf = (char*)buf_;
  while(len) {
    int err = write(client_fd, buf, len);
    if (err < 0 && errno == EINTR) continue;
    if (err < 0) fatal("write()");
    len -= err;
    buf += err;
  }
}  

void write_finish(int status)
{
  write_int(MSG_FINISH);
  write_int(status);
  if (status) exit(1);
}
void write_text(char* str)
{
  write_int(MSG_TEXT);
  write_str(str);
}
void write_prompt(int echo)
{
  write_int(MSG_PROMPT);
  write_int(echo);
}
void write_reply(char* str)
{
  write_int(MSG_REPLY);
  write_str(str);
}
void write_str(char* str)
{
  size_t len = strlen(str);
  if (len > INT_MAX) len = INT_MAX;
  write_int((int)len);
  writebuf_(str, (int)len);
} 
void write_int(int i)
{
  writebuf_(&i, sizeof(i));
}
int read_msg_type() { return read_int(); }
char* read_reply()
{
  if (read_int() != MSG_REPLY) fatal("bad msg id");
  return read_str();
}
char* read_str()
{
  int len = read_int();
  char* buf = malloc(len+1);
  if (!buf) fatal("malloc()");
  buf[len] = '\0';
  readbuf_(buf, len);
  return buf;
}
int read_int()
{
  int i;
  readbuf_(&i, sizeof(i));
  return i;
}


