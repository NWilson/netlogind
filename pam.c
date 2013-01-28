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
#include <stdio.h>
#include <errno.h>

#if HAVE_PAM

#if HAVE_PAM_PAM_APPL_H
#include <pam/pam_appl.h>
#elif HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#if defined(__sun) || defined(__hpux) || defined(_AIX)
#define SUN_PAM
#define PAM_CONST
#else
#define PAM_CONST const
#endif

#if defined(__sun) || defined(__hpux)
#define SUN_RPC_PAM_BUG
#endif

#if defined(__sun)
#define SUN_PAM_TTY_BUG
#endif

#if defined(_AIX) || defined(__sun)
/* We need euid root, always, to update unix passwords. On most systems, the
 * ruid doesn't matter.
 *    - On AIX: if ruid == 0, checks are bypassed; on the other hand, if we
 *      use ruid of user, we have to enter the old password (even if we just
 *      gave it in pam_authenticate). This may be new on AIX 5.2/5.3 (dtucker
 *      suggests older AIX requires ruid of root to change password at all!?)
 *    - On Sun: similarly, complexity checks and knowledge of old password are
 *      bypassed when ruid is root. */
#define CHAUTHTOK_CHECKS_RUID 1
#endif

static pam_handle_t* pam_h = 0;
static int authenticated = 0, setcred = 0, opened_session = 0,
    last_status = PAM_SUCCESS;
static int pam_conv_fd = -1;
static int conv_reject_prompts = 0;

static int conv_fn(int num_msg, PAM_CONST struct pam_message** msg_,
                   struct pam_response** resp_, void* appdata_ptr)
{
  if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG) return PAM_CONV_ERR;

  debug("(%sPAM conversation called)", pam_conv_fd < 0 ? "Null " : "");

  struct pam_response* resp = malloc(num_msg * sizeof(*resp));
  if (!resp) return PAM_BUF_ERR;

  int i;
  for (i = 0; i < num_msg; ++i) {
#ifdef SUN_PAM
    /* In Sun-derived libpam, "pam_message**" is a pointer to an array. */
    struct pam_message* msg = &((*msg_)[i]);
#else
    /* It's an array of pointers otherwise. */
    PAM_CONST struct pam_message* msg = msg_[i];
#endif
    resp[i].resp_retcode = 0;
    resp[i].resp = 0;
    switch (msg->msg_style) {
    case PAM_PROMPT_ECHO_OFF:
    case PAM_PROMPT_ECHO_ON:
      debug("  Prompt(e=%d): %s",
            msg->msg_style==PAM_PROMPT_ECHO_OFF ? 0 : 1,
            msg->msg);
      if (pam_conv_fd >= 0) {
        if (conv_reject_prompts) goto bail;
        if (write_text(pam_conv_fd, msg->msg) < 0 ||
            write_prompt(pam_conv_fd, msg->msg_style == PAM_PROMPT_ECHO_ON) < 0)
          goto bail;
        resp[i].resp = read_reply(pam_conv_fd);
        if (!resp[i].resp) goto bail;
        if (strlen(resp[i].resp)+1 > PAM_MAX_RESP_SIZE) goto bail;
      }
      break;
    case PAM_ERROR_MSG:
    case PAM_TEXT_INFO:
      debug("  %s: %s",
            msg->msg_style==PAM_ERROR_MSG ? "Error" : "Info",
            msg->msg);
      if (pam_conv_fd >= 0) {
        if (write_text(pam_conv_fd, msg->msg) < 0)
          goto bail;
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

  if (pam_conv_fd >= 0) {
    *resp_ = resp;
    return PAM_SUCCESS;
  }

  if (i == num_msg) i = num_msg-1;

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
#ifdef SUN_PAM_TTY_BUG
  if ((rv = pam_set_item(pam_h, PAM_TTY, "/dev/nld")) != PAM_SUCCESS)
    fatal("pam_set_item(PAM_TTY,/dev/nld");
#endif

  pam_conv_fd = fd;
  if ((rv = pam_authenticate(pam_h, 0)) != PAM_SUCCESS) {
    debug("pam_authenticate(): %s", pam_strerror(pam_h, rv));
    pam_conv_fd = -1;
    return -1;
  }

  rv = pam_acct_mgmt(pam_h, 0);

  char* pam_user = 0;
  if ((rv = pam_get_item(pam_h, PAM_USER, (PAM_CONST void**)&pam_user)) !=
               PAM_SUCCESS)
  {
    pam_user = 0;
    debug("pam_get_item(PAM_USER): %s", pam_strerror(pam_h, rv));
  } else if (!(pam_user = strdup(pam_user))) fatal("malloc()");
  else {
    free(*username);
    *username = pam_user;
  }

  if (rv == PAM_NEW_AUTHTOK_REQD) {
    debug("pam_acct_mgmt(): PAM_NEW_AUTHTOK_REQD for %s", *username);
#if CHAUTHTOK_CHECKS_RUID
    struct passwd pw, *pwp;
    char pw_buf[1024];
    rv = getpwnam_r(*username, &pw, pw_buf, sizeof(pw_buf), &pwp);
    if (!pwp) {
      if (rv) {
        errno = rv;
        perror("Fetching user for pam_chauthtok failed. getpwnam_r()");
      } else debug("Fetching user for pam_chauthtok failed: not found");
      pam_conv_fd = -1;
      return -1;
    }
    if (setreuid(pw.pw_uid,-1) < 0)
      perror_fatal("setreuid() for pam_chauthtok failed");
#endif
    rv = pam_chauthtok(pam_h, PAM_CHANGE_EXPIRED_AUTHTOK);
#if CHAUTHTOK_CHECKS_RUID
    if (setreuid(0,-1) < 0)
      perror_fatal("setreuid() after pam_chauthtok failed");
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

  authenticated = 1;
  return 0;
}

int pam_begin_session(const char* username, int fd)
{
  int rv, i;
  if (!pam_h &&
      (rv = pam_start(PAM_APPL_NAME, username, &conv, &pam_h)) != PAM_SUCCESS)
    fatal("pam_start() failure: %d", rv);
#ifdef SUN_PAM_TTY_BUG
  if ((rv = pam_set_item(pam_h, PAM_TTY, "/dev/nld")) != PAM_SUCCESS)
    fatal("pam_set_item(PAM_TTY,/dev/nld");
#endif

  conv_reject_prompts = 1;
  pam_conv_fd = fd;

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
        if (authenticated) {
          pam_conv_fd = -1;
          return -1;
        }
      } else {
        setcred = 1;
      }
    } else {
      if ((rv = pam_open_session(pam_h, 0)) != PAM_SUCCESS) {
        debug("pam_open_session(): %s", pam_strerror(pam_h, rv));
        if (authenticated) {
          pam_conv_fd = -1;
          return -1;
        }
      } else {
        opened_session = 1;
      }
    }
  }
  pam_conv_fd = -1;
  return 0;
}


void pam_export_environ()
{
  if (!pam_h) return;

#if HAVE_PAM_GETENVLIST
  /* XXX should we really prevent MAIL, PATH set through PAM? */
  static char* banned_env[] = {"SHELL", "HOME", "LOGNAME", "MAIL", "CDPATH",
                               "IFS", "PATH", "LD_", 0 };

  char **pam_env = pam_getenvlist(pam_h), **env;
  if (!pam_env) { debug("pam_getenvlist() failed"); return; }
  for (env = pam_env; *env; ++env) {
    char** banp;
    for (banp = banned_env; *banp; ++banp)
      if (strncmp(*env, *banp, strlen(*banp)) == 0)
      { free(*env); continue; }
    putenv(*env);
  }
  free(pam_env);
#endif
}

void pam_cleanup(uid_t uid)
{
  int rv;
  if (!pam_h) return;
  if (setcred) {
#ifdef SUN_RPC_PAM_BUG
    /* Horrendous bug in pam_unix, observed on Solaris and HP-UX. It checks
     * for the current euid (confirmed in source) instead of PAM_USER, leading
     * to a "permission denied" error, and the highly unique error reported
     * via the conversation function:
     *     Removing root credentials would break the rpc services that
     *     use secure rpc on this host!
     *     root may use keylogout -f to do this (at your own risk)!
     *
     * After setting the euid to the user, you'll still get piles of
     * "Authentication failed" errors on HP-UX at least, with the message:
     *     Could not unset your secret key.
     *     Maybe the keyserver is down?
     * I think these are benign. */
    if (setreuid(-1,uid) < 0)
      perror("PAM_DELETE_CRED workaround failed. setreuid()");
#endif
    if ((rv = pam_setcred(pam_h, PAM_DELETE_CRED)) != PAM_SUCCESS)
      debug("pam_setcred(PAM_DELETE_CRED): %s", pam_strerror(pam_h, rv));
#ifdef SUN_RPC_PAM_BUG
    if (setreuid(-1,0) < 0)
      perror("PAM_DELETE_CRED workaround: restering root failed. setreuid()");
#endif
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
