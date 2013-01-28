Functions performed by netlogind
================================

The basic task of a daemon providing logins is to execute one or more commands in the correct context for a user, for that system. This is harder than it seems, given historical requirements derived from terminal logins, and differences in process attributes and credentials between platforms. Different steps must be precisely ordered to ensure correct set-up.

We describe here the steps performed by netlogind, the APIs invoked, and the ordering constraints between the calls.

## Most basic steps to create a process running as a given user

    struct passwd pw; //< the user
    setgid(pw.pw_gid);
    initgroups(pw.pw_name, pw.pw_gid);
    setuid(pw.pw_uid);

(Error checking should be done.) In addition, for highly security-critical calls such as setuid, call `getuid` and `geteuid` afterwards to assert that the correct credentials were set. Continuing to execute code under the wrong uid is the worst disaster of all. `setuid` resets the saved-set-userid on all platforms where this is supported.

This does launch a process "as a given user" in a very rudimentary sense, but on most platforms, the resulting context is still very different from that obtained by the normal, platform-specific, way of obtaining a logon. In particular, for launching a shell or general user session, this is not sufficient.

## PAM

PAM is an API allowing system administrators to configure how applications perform authentication and launch user processes. PAM is widely deployed.

PAM is used to set up session environment through the `pam_setcred` and `pam_open_session` functions. There are many issues with calling these functions portably, and constraints on the order.

* They must be called from the same thread of execution as `pam_authenticate` if that was used to perform authentication. Some modules work by collecting credentials during the authentication conversation, and performing an action with them during the session phase (eg `pam_mount`). In particular, PAM modules that use `pam_set_data` internally will not work if `pam_setcred/open_session` is called from a different process to `pam_authenticate` (for example, some versions of `pam_afs` or `pam_krb5`).
* They must be called as root.
* They must be called after `initgroups`, as they may be used to set up extra group memberships.
* There is debate over which order `pam_setcred` and `pam_open_session` should be called in. It seems preferable to invoke `pam_setcred` before `pam_open_session` on most modern platforms, as some modules reasonably require this.[(\*)](http://www.redhat.com/archives/pam-list/2001-November/msg00054.html) However, there are reasons for wanting to order it the other way.[(\*)](https://bugzilla.mindrot.org/show_bug.cgi?id=926#c6) Regardless, the strictest constraint is that Solaris and HP-UX PAM will fail with certain modules unless `pam_setcred` comes second, so there is no much choice on those platforms (that is, you actually have to follow the order documented on those platforms). LinuxPAM's documentation says that `pam_setcred` should come first, the opposite to OpenPAM's documentation.
* Ordering of `pam_open_session/setcred` relative to forking: fork with care between calling the PAM functions and `setuid`. If calling `fork`, after `pam_open_session` and before `setuid`, guard the fork with a `setresuid(uid,-1,-1)` (or similar) just before the fork and restore the privileged uid just after. This is because `pam_limits` applies resource limits to the calling process based on the real uid. If the target user has a limit applied on the number of processes, but root is already running more than the user is allowed to, the fork will fail because the user's limit is being tested against root's process count.
* PAM bugs to be aware of: some vendor-supplied modules, eg on HP-UX, do not pass the appdata parameter to the conversation function. For portability, use a static variable instead to avoid relying on the appdata parameter. Other notable real-world compatibility issues: [RedHat #126985](https://bugzilla.redhat.com/show_bug.cgi?id=126985), [RedHat #127054](https://bugzilla.redhat.com/show_bug.cgi?id=127054)
* The `PAM_TTY` issue on Sun: (eg [OpenSSH #687](https://bugzilla.mindrot.org/show_bug.cgi?id=687), [thread](http://thr3ads.net/openssh-unix-dev/2001/10/1177879-Regarding-PAM_TTY_KLUDGE-and-Solaris-8)). My understanding of the solution is that PAM_TTY should be exposed as a parameter on the relevant systems so users have the power to enable the workaround if they need to. It is definitely required for `PAM_TTY` to be set to a string beginning with `"/dev/"` on some versions of Solaris, including Solaris 10 in my testing. On Linux, the workaround is only needed to avoid problems in specific modules (eg. `pam_time`).
* Very nasty issues with `pam_setcred(DELETE_CRED)` on HP-UX and Solaris, where `pam_unix` uses the uid of the process, rather than the `PAM_USER` field. Workaround is to seteuid for that call. HP-UX still spews an unnecessary message in this case about it not being able to delete the user's credentials. All these have specific error messages that can be googled, sadly.
* There are ruid restrictions on `pam_chauthtok` (AIX requires ruid of 0 on old versions, but matches Solaris behaviour on 5.2+, Solaris requires ruid non-zero or else complexity restrictions are not checked, nor is the user prompted for his old password).

## Setting up the execution environment for a user process

### `closefrom`

Close all fds before exec'ing the user's command. Whether this should be done is debated, because it kills many implementations of `posix_trace` (for example). Although sometimes listed as one of the steps for daemonizing a process, it's a very paranoid thing to do. It's more justifiable to do though when creating a user session.

_Platforms:_ native on Solaris, FreeBSD. Otherwise, emulate using fds listed in `proc` if available. On no account naively try to close up to `getrlimit(RLIMIT_NOFILE)` or similar, as this can be far too large a number to loop up to.

_Call at:_ any time

_See also:_
 * [Austin Group Defect Tracker, "Add fdwalk system interface"](http://www.austingroupbugs.net/view.php?id=149)
 * [StackOverflow: "Getting the highest allocated file descriptor"](http://stackoverflow.com/questions/899038/), a guide showing how to implement a `closefrom()` function on each platform

### `setlogin`

Invoke `setlogin(pw.pw_name)` to ensure that the session has the correct name associated with it.

_Call:_ Right after a `setsid`; absolutely not from the same session the daemon is running in. Call as root.

_Platforms:_ FreeBSD, Mac OS X. Because one uid may have several entries in the password database with different names, `getpwuid(getuid())` mightn't tell you the username that was used to log on, so another function, `getlogin`, has to be provided to do this. The implementation may be done in terms of utmp (unreliable), or `$LOGNAME` (insecure). BSD-derived systems solve the problem in the ideal way by storing a username in the per-session kernel data structure. AIX solves this using `usrinfo` (below)

### _AIX:_ `usrinfo`, `setpcred`

On AIX, call `usrinfo(SETUINFO, "LOGIN=<name>\0LOGNAME=<name>\0NAME=<name>\0\0", ...)`. This is similar in function to `setlogin` on BSD-derived systems. Call as root. Some applications apparently require `TERM` to be set too, but there may be no reasonable value to give it.

Use `setpcred(pw.pw_name, NULL)` to set up process limits and all process credentials correctly from the credentials in the user database. Use the second parameter to override specific credentials, for example, passing `{ "REAL_USER=root", 0 }` instead of `NULL` for the second parameter overrides setting the uid only, which can be done later with `setuid()`.

### Environment variables

`$USER`, `$HOME`, `$PATH`, `$LOGNAME`, `$SHELL`, `$LOGIN` (legacy, AIX)

Optional: `$MAIL`, `$TZ`

Defaults may be in `/etc/environment`. Remember to read the variables set through PAM with `pam_getenvlist`, since some modules set crucial variables (eg. `$KRB5CCACHE`), and certain other authentication methods (eg. GSSAPI) may also define variables for the child to use (`$KRB5CCACHE` again being the main one).

The manpage for Solaris `login` explains that it does not allow certain variables to be set through PAM: `$SHELL`, `$HOME`, `$LOGNAME`,  `$MAIL`, `$CDPATH`, `$IFS`, and `$PATH`. This is probably sensible, and many other implementations have adopted this. Also, all variables beginning with `"LD_"` are blocked in this and other implementations (including Mac OS X's `login`).

### SELinux

Setting the SELinux context of the child process is best done through PAM on Linux systems. It usually is achieved through `setexeccon()`, which does not alter the parent process's context, but sets it up to be applied on the next `exec()`. The complication is the the session functionality of some PAM modules is meant to be called under the user's SELinux context, but not for other modules. This requires very careful configuration of the PAM stack. In fact, `pam_selinux` has 'open' and 'close' arguments as a hack to allow its order in the stack to be different when `pam_session_open` and `pam_session_close` are called, precisely because the order is so delicate.

*_TODO_* Work out what's necessary here

An application may still wish to set the execution context itself though, to guarantee that the system context is not passed on to users with a different default context. The API calls in this case would be:
* `getseuserbyname()` to fetch the SELinux username and level
* `get_default_context_with_level()` for this user
* `setexeccon()`

### Mach namespace

*Work In Progress*

On Mac OS X, procesess ("tasks") have associated ports, which are similar in some ways to datagram pipes between processes, but operating on a rather different model. A new process does not inherit its parent's ports, except for a few ports associated with special fields. This includes the exception port and bootstrap port. The exception port should be reset so that the Apple crash handler receives core dumps of user processes (this is turned off for daemons). The bootstrap port needs to be carefully set. The bootstrap namespace needs to be carefully set, to associate the process with the correct context.

These functions may be done directly by an application (Screen Sharing) or through PAM (`pam_launchd`).

### Audit userid

On some kernels, processes maintain an auid, an additional userid which is preserved when the user switches userid using `su`(1), for example. This permits actions taken to be logged and traced to the user who performed it.

_On Linux:_ The auid is typically set using `pam_loginid`. But, to guarantee it is set even when PAM is not configured correctly, a daemon should write the user's uid to `/proc/self/loginuid` before exec'ing the user's session. The point is that whether or not the sysadmin remembers to add the module to the service's configuration, the kernel still has the field in its process entry, so setting it is not optional. A daemon must attempt to initialise ever uid for the processes it is launching. PAM can be then used to configure the disposition of the service on error, and to interact with user-space components: while the daemon may be lenient, `pam_loginuid` may block the login if, for example, the system administrator wishes to require the user-space auditd to be running.

_See further:_ ["The Linux Audit System, or Who Changed That File?"](http://la-samhna.de/library/audit.html), Rainer Wichmann

_On Solaris, Mac OS X, and FreeBSD:_ The kernel also assigns an auid to processes. It should be set through the BSM audit API (see `setaudit_addr`). The API has some differences on different platforms:
* Very old platforms, pre-IPv6, use `setaudit`, a narrower variant of the API.
* Solaris's `auditinfo_addr_t` has no `ai_flags` field. Be aware that setting the four fields in the Solaris documentation will not completely initialise the structure in the OpenBSM implementation. For portability, call `getaddr_info` and then modify the relevant fields.
* On Mac OS X, the kernel will give you a uniquely-generate session id if the `ai_asid` field is set to `AU_ASSIGN_ASID`. On other platforms, generate one yourself to create a new audit session (eg. `getpid()` or `getsid()`).

### _Solaris:_ `contract`(4)

*Work in progress*

Create a new contract for processes launched from a daemon. otherwise, critical events in one user's session could result in all users' sessions being killed.

_See example:_ ["Creating subprocesses in new contracts on Solaris 10"](http://blog.devork.be/2011/02/creating-subprocesses-in-new-contracts.html), Floris Bruynooghe

### _Solaris:_ `project`(4)

On Solaris, projects are used to set resource limits for groups of processes. A user session spawned from a daemon should have its project changed from the system project to that of the user.

The usual way to accomplish this is with PAM. Sun's `pam_unix_cred` puts the session process into the user's default project; alternatively, `pam_user_project` could be used to create and manage per-user projects on-the-fly.

Therefore, the theory behind netlogind's implementation is that actually performing the project initialisation is best left to the admin's preferred configuration. A daemon need do no more than check the user is allowed to run processes in the project, after PAM session management is complete. This just avoids the case that a misconfigured PAM stack allows a user to chew up unlimited processes in the "system" project.

To do this:
* Call `getprojid()` then `getprojbyid()` to identify our project.
* Call `inproj()` to check that continuing with this project is allowed according to the user's privileges.

From [OpenSSH bug #1824](https://bugzilla.mindrot.org/show_bug.cgi?id=1824), the library calls utilized to put a process into a user's default project would be:
>  * `getdefaultproj()`: Obtains the default project for the user logging in.
>  * `setproject()`: Sets the project for the session. Requires special privs (uid=0) or will fail.

### _BSD:_ `login_cap`

Many of these tasks are factored out of `login(1)` into libutil on BSD systems. See `setusercontext()`, `login_cap`(3) documentation.
