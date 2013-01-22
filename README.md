netlogind
=========

### A test-harness, cross-platform, login daemon

## Purpose

Netlogind is a simple daemon that accepts connections, converses with a client, and runs commands on-demand from the client. It models the sort of interactions that might take place in a remote access program, for example.

It is a learning example, but demonstrates how session initialisation could be done in a real program. It fills the gap of a simple-to-understand example of how to launch a process as a user, from a root daemon. (This is a surprisingly hard task, with a lot of platform-specific code, and not well documented.) Netlogind does not bother with a protocol of any particular expressive power, nor does it need to mess with encryption, as all communication is done over UNIX-domain sockets. In this way, hopefully netlogind can serve as a model for testing and review without the clutter encountered by real-world applications or protocols.

It also functions a test harness for PAM, and simulating logins generally.

It is not intended for any production use.

## Functions

Netlogind should support all the platform's native features for launching user sessions. This is not entirely straightforward. A preliminary list of functions is documented on unix.stackexchange, ["How do I write a login daemon?"](http://unix.stackexchange.com/questions/61945/how-do-i-write-a-login-daemon).

The functionality implemented here is clearly not definitive, but I'd like to accept any feedback that could make it more thorough.

## Supported platforms (and later)

* Linux 2.4
* FreeBSD 7
* Solaris 5.8
* _Darwin 10.5 — coming soon_
* _HP-UX 11.00 — coming soon_
* _AIX 5.3 — coming soon_
* _no interest in adding support for IRIX, SCO, Digital/OSF/Tru64, …_

## Acknowledgements

I have trawled through mailing list postings for various projects, and picked through the implementation of `login`(1) and `telnetd`(8) for each platform I could find. I should particularly thank OpenSSH, a widely-ported application with a very good security model. The bugs its developers have found and worked through on each platform and its code are an invaluable reference.

While inspecting other implementations from real or historical applications, I took notes. I then sat down at home and hammered out my own quick invocation of each platform's API, distinguishable from the original in each case by being shorter and cruder. In this way, I don't believe myself to have duplicated any lines of code.

I am not aware of any other applications using the same process structure as netlogind. In particular, the way it uses the "session thread" may be original. I'm surprised that what appears to me to be a secure and fairly sensible design doesn't appear to be more widely used, from the applications I read.

## Design

Modern daemons have security requirements and complexity far exceeding their historical predecessors. They are expected to use a structure of cooperating processes to achieve privilege minimisation, particularly in code handling client input.

netlogind has a relatively simple structure. It is a forking daemon, with the main listener running as root, since it will later need to change uid once the client authenticates. After authentication, it goes into command loop, reading strings from the client and executing them as commands.

### A simplistic design

        netlogind (listener)
            |
       forks child (detached)
            |
            |-------------------------------------------> [session] process
           ***                  socketpair,fork               |
            |                                                 |
    +----------------+                                        |
    | authentication |                                        |
    |      ...       |                                        |
    |      ...       |  <.................................>   |
    |                |    (some authentication methods        |
    +----------------+     may communicate with the root      |
            |              [session] process to set up        |
            |              context)                           |
            |                                                 |
            |                                                 |
    +----------------+                                +---------------+   fork,setuid,exec
    |  command loop  |  ----------------------------> | read commands | -------------------->
    |      ...       |                                |      ...      |
    |      ...       |  ----------------------------> |      ...      | -------------------->
    |                |                                +---------------+
    +----------------+                                        |
          (exit)                                       clean up session
                                                       context as root

This layout has some benefits. For a start, note that it satisfies all our requirements regarding platform features and PAM. By running all the parts of the PAM flow in a single thread of execution, on the same PAM handle, we guarantee interoperability with all sane modules. Similarly, all parts of the platforms' APIs can be hooked in during the session process to ensure that the commands we launch are genuinely run in the correct context, with all the environment and process credentials they may need. Placing the PAM flow in the session process simplifies the mechanics of carrying out the PAM conversation with the client. Also, the parent process could quite easily be running a non-forking server and handling several clients, each with their own session process, set up with the required execution context for user processes and kept available for forking off commands during the connection.

The problems are with security. We would like to follow privilege minimisation, but in this example, the root main process is interpreting client input, and stays root for longer than needed. The concern with doing protocol parsing in the main process is understandable in real-world applications where this may involve running input from authenticated clients through compression or cryptographic libraries.

### Better designs

#### Drop root immediately
* We can't on any account create a process under the client user's requested uid before authentication has completed.
* We could drop privileges to a daemon account with no rights straight after launching the session process, at point (\*\*\*) above, optionally chroot'ing to `/var/empty`.

#### Keep root, but use privilege separation
<ul>
<li>Losing root privileges straight away (after creating the session process) doesn't work if our application protocol requires us later to perform tasks as root, or as the user.
<li>In these cases, we can use the <em>privilege separation</em> design to avoid processing untrusted client input in the root process.
<li>The root process forks, then drops privileges. The child process is trustworthy (because it was forked from our process image!), so it's safe to parse input from it in the parent. The child reads messages from the client, decompresses or decrypts them, then forwards the messages to the main process. For efficiency, mapped-memory and semaphores (or similar) are usually used here.
<li>After authentication, the main process may then do whatever it needs to do.
</ul>

                        netlogind (listener)
                            |
                       forks child (detached)
                            |
                            |----------------------> [session] process
    [net] process <---------|                            |
     ***            +----------------+                   |
      |             | authentication |                   |
      | <.........> |      ...       |                   |
      |             |      ...       |  <............>   |
      | <.........> |                |                   |
      -             +----------------+                   |
                            |                            |

At point (\*\*\*), we switch to an unprivileged uid (daemon account) for reading client input, communicate with the parent process, and exit after authentication. Note that any connection context will have to be transferred back to the parent at this point.

Now the user has authenticated, the main process can do what it needs to do as root, then drop privileges itself to the daemon account or the authenticated user's account. It could transfer the connection to a child spun off from the session process, and remain root as long as it is not interpreting client input through untrusted libraries, or launch another privilege-separated helper.

We will not explore all these options in netlogind. The essential idea is simply that as an example application, our use of the session process design is still applicable to modern application requirements with sophisticated isolation of components in multiple processes.

## Bugs

* Large chunks not yet implemented
* Doesn't compile on all platforms
* No timeouts: each user should have a connection limit, and unauthenticated connections should be given only limited time
