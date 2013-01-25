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

#ifndef NET_H__
#define NET_H__

int is_un_connectable(const char* sock);
int un_listen(const char* sock);
int un_connect(const char* sock);

#define MSG_FINISH 1
#define MSG_TEXT 2
#define MSG_PROMPT 3
#define MSG_REPLY 4

/*
 * Blindingly simple blocking, unbuffered network layer.
 *
 * The write_ functions return 0 on success.
 * The read functions return -1 (int) or 0 (char*) or failure.
 */
int write_finish(int fd, int status);
int write_text(int fd, const char* str);
int write_prompt(int fd, int echo);
int write_reply(int fd, const char* str);
int write_str(int fd, const char* str);
int write_uint(int fd, int i);
int read_msg_type(int fd);
char* read_reply(int fd);
char* read_str(int fd);
int read_uint(int fd);

#endif
