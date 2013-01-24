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

#include "pam.h"
#include "util.h"
#include "net.h"

#include <stdlib.h>

#if HAVE_PAM

#if HAVE_PAM_PAM_APPL_H
#include <pam/pam_appl.h>
#elif HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#if defined(__sun) || defined(__hpux)
// XXX is this AIX too?
#define SUN_PAM
#define PAM_CONST
#else
#define PAM_CONST const
#endif
#if defined(_AIX) || defined(__sun)
// XXX AIX too? DTucker's page says it needs it, but elsewhere it says it
//     needs the opposite...
#define CHAUTHTOK_CHECKS_RUID 1
#endif

static pam_handle_t* pam_h = 0;
static int authenticated = 0, setcred = 0, opened_session = 0,
    last_status = PAM_SUCCESS;
static int pam_conv_fd = -1;

static int conv_fn(int num_msg, PAM_CONST struct pam_message** msg_,
                   struct pam_response** resp_, void* appdata_ptr)
{
  if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG) return PAM_CONV_ERR;

  if (pam_conv_fd < 0) return PAM_CONV_ERR;

  if (debug_ && write_text(pam_conv_fd, "...PAM conv:\n") < 0)
    return PAM_CONV_ERR;

  struct pam_response* resp = malloc(num_msg * sizeof(*resp));
  if (!resp) return PAM_BUF_ERR;

  int i;
  for (i = 0; i < num_msg; ++i) {
#ifdef SUN_PAM
    struct pam_message* msg = &((*msg_)[i]);
#else
    PAM_CONST struct pam_message* msg = msg_[i];
#endif
    resp[i].resp_retcode = 0;
    resp[i].resp = 0;
    switch (msg->msg_style) {
    case PAM_PROMPT_ECHO_OFF:
    case PAM_PROMPT_ECHO_ON:
      if (write_text(pam_conv_fd, msg->msg) < 0 ||
          write_prompt(pam_conv_fd, msg->msg_style == PAM_PROMPT_ECHO_ON) < 0)
        goto bail;
      resp[i].resp = read_reply(pam_conv_fd);
      if (!resp[i].resp) goto bail;
      if (strlen(resp[i].resp)+1 > PAM_MAX_RESP_SIZE) goto bail;
      break;
    case PAM_ERROR_MSG:
    case PAM_TEXT_INFO:
      if (write_text(pam_conv_fd, msg->msg) < 0)
        goto bail;
      {
        size_t len = strlen(msg->msg);
        if (len > 0 && msg->msg[len-1] != '\n' &&
            write_text(pam_conv_fd, "\n") < 0)
        goto bail;
      }
      break;
    default:
      goto bail;
    }
  }

  *resp_ = resp; 
  return PAM_SUCCESS;

bail:
  for (; i >= 0; --i) {
    if (!resp[i].resp) continue;
    buffer_scrub(resp[i].resp, strlen(resp[i].resp));
    free(resp[i].resp);
  }
  buffer_scrub(resp, num_msg * sizeof(*resp));
  free(resp);

  return PAM_CONV_ERR;
}

PAM_CONST struct pam_conv conv = { &conv_fn, 0 };

int pam_authenticate_session(char** username, int fd)
{
  int rv;
  if ((rv = pam_start(PAM_APPL_NAME, *username, &conv, &pam_h)) != PAM_SUCCESS)
    fatal("pam_start() failure: %d", rv);

  pam_conv_fd = fd;
  if ((rv = pam_authenticate(pam_h, 0)) != PAM_SUCCESS) {
    debug("pam_authenticate(): %s", pam_strerror(pam_h, rv));
    pam_conv_fd = -1;
    return -1;
  }
  if ((rv = pam_acct_mgmt(pam_h, 0)) == PAM_NEW_AUTHTOK_REQD) {
    debug("pam_acct_mgmt(): PAM_NEW_AUTHTOK_REQD");
#if CHAUTHTOK_CHECKS_RUID
    ...
#endif
    rv = pam_chauthtok(pam_h, PAM_CHANGE_EXPIRED_AUTHTOK);
#if CHAUTHTOK_CHECKS_RUID
    ...
#endif
    if (rv != PAM_SUCCESS) {
      debug("pam_chauthtok(PAM_CHANGE_EXPIRED_AUTHTOK): %s",
            pam_strerror(pam_h, rv));
      pam_conv_fd = -1;
      return -1;
    }
  } else if (rv != PAM_SUCCESS) {
    debug("pam_acct_mgmt(): %s", pam_strerror(pam_h, rv));
    pam_conv_fd = -1;
    return -1;
  }
  pam_conv_fd = -1;

  char* pam_user = 0;
  if ((rv = pam_get_item(pam_h, PAM_USER, (PAM_CONST void**)&pam_user)) != PAM_SUCCESS)
    debug("pam_get_item(PAM_USER): %s", pam_strerror(pam_h, rv));
  else if (!(pam_user = strdup(pam_user)))
    fatal("malloc()");
  else {
    free(*username);
    *username = pam_user;
  }

  authenticated = 1;
  return 0;
}

int pam_begin_session(const char* username)
{
  int rv, i;
  if (!pam_h &&
      (rv = pam_start(PAM_APPL_NAME, username, &conv, &pam_h)) != PAM_SUCCESS)
    fatal("pam_start() failure: %d", rv);

  /* On Solaris and HP-UX, the docs say we can't call setcred first, and the
   * modules actually enforce that. LinuxPAM says we must call setcred first,
   * and that's preferable, so we do it in all other cases. */
#ifdef SUN_PAM
  int setcred_first = 0;
#else
  int setcred_first = 1;
#endif

  for (i = 0; i < 2; ++i) {
    if (i != setcred_first) {
      if ((rv = pam_setcred(pam_h, PAM_ESTABLISH_CRED)) != PAM_SUCCESS) {
        debug("pam_setcred(PAM_ESTABLISH_CRED): %s", pam_strerror(pam_h, rv));
        if (authenticated) return -1;
      } else {
        setcred = 1;
      }
    } else {
      if ((rv = pam_open_session(pam_h, 0)) != PAM_SUCCESS) {
        debug("pam_open_session(): %s", pam_strerror(pam_h, rv));
        if (authenticated) return -1;
      } else {
        opened_session = 1;
      }
    }
  }
  return 0;
}

static char* banned_env[] = {"SHELL", "HOME", "LOGNAME", "MAIL", "CDPATH",
                             "IFS", "PATH", "LD_", 0 };

void pam_export_environ()
{
  if (!pam_h) return;

  char **pam_env = pam_getenvlist(pam_h), **env;
  if (pam_env) { debug("pam_getenvlist() failed"); return; }
  for (env = pam_env; *env; ++env) {
    char** banp;
    for (banp = banned_env; *banp; ++banp)
      if (strncmp(*env, *banp, strlen(*banp)) == 0)
      { free(*env); continue; }
    putenv(*env);
  }
  free(pam_env);
}

void pam_cleanup()
{
  int rv;
  if (!pam_h) return;
  if (setcred) {
    if ((rv = pam_setcred(pam_h, PAM_DELETE_CRED)) != PAM_SUCCESS)
      debug("pam_setcred(PAM_DELETE_CRED): %s", pam_strerror(pam_h, rv));
  }
  if (opened_session) {
    if ((rv = pam_close_session(pam_h, 0)) != PAM_SUCCESS)
      debug("pam_close_session(): %s", pam_strerror(pam_h, rv));
  }
  if ((rv = pam_end(pam_h, last_status)) != PAM_SUCCESS)
    fatal("pam_end(%d): %d", last_status, rv);
  pam_h = 0;
}

#endif
