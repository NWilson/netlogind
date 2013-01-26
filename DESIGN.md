Design notes
============

Modern daemons have security requirements and complexity far exceeding their historical predecessors. They are expected to use a structure of cooperating processes to achieve privilege minimisation, particularly in code handling client input.

The netlogind has a relatively simple structure. It is a forking daemon, with the main listener running as root, since it will later need to change uid once the client authenticates. After authentication, it goes into command loop, reading strings from the client and executing them as commands.

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
