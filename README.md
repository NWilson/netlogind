netlogind
=========

### A test-harness, cross-platform, login daemon

## Purpose

The netlogind is a simple daemon that accepts connections, converses with a client, and runs commands on-demand from the client. It models the sort of interactions that might take place in a remote access program, for example.

It is a learning example, but demonstrates how session initialisation could be done in a real program. It fills the gap of a simple-to-understand collection of sample code on how to launch a process as a user, from a root daemon. (This is a surprisingly hard task, with a lot of platform-specific code, and not well documented.) The netlogind does not bother with a protocol of any particular expressive power, nor does it need to mess with encryption, as all communication is done over UNIX-domain sockets. In this way, hopefully netlogind can serve as a model for testing and review without the clutter encountered by real-world applications or protocols.

It also functions a test harness for PAM, and simulating logins generally.

It is not intended for any production use.

## Functionality

The netlogind aims to demonstrate how to support the various platforms' native features for launching user sessions. See [a complete list](FUNCTIONALITY.md).

The functionality implemented here may not be complete. I'd like to accept any feedback that could make it more thorough!

## Design

Modern daemons have security requirements and complexity far exceeding their historical predecessors. We discuss in the [design notes](DESIGN.md) issues of how to structure a login daemon.

## Supported platforms (and later)

* Linux 2.4
* FreeBSD 7
* Solaris 5.8
* Darwin 10.5
* HP-UX 11.00
* AIX 5.3
* _I have no interest in adding support for IRIX, SCO, Digital/OSF/Tru64, …_

## Acknowledgements

I have trawled through mailing list postings for various projects, and picked through the implementation of `login`(1) and `telnetd`(8) for each platform I could find. I should particularly thank OpenSSH, a widely-ported application with a very good security model. The bugs its developers have found and worked through on each platform and its code are an invaluable reference.

While inspecting other implementations from real or historical applications, I took notes. I then sat down at home and hammered out my own quick invocation of each platform's API, distinguishable from the original in each case by being shorter and cruder. In this way, I don't believe myself to have duplicated any lines of code.

I am not aware of any other applications using the same process structure as netlogind. In particular, the way it uses the "session thread" may be original. I'm surprised that what appears to me to be a secure and fairly sensible design doesn't appear to be more widely used, from the applications I read.
