[![es](https://img.shields.io/badge/lang-es-yellow.svg)](https://github.com/ThomasMiz/socks5-server/blob/main/README.md)

# Socks5 Server

The developed application is a proxy server that implements the SOCKSv5 protocol [[RFC1928]](https://www.rfc-editor.org/rfc/rfc1928 "[RFC1928]") and its associated functionalities with an additional protocol that allows managing and obtaining relevant information from the server. The proxy supports a series of requirements dictated by the chair of [72.07] - Communication Protocols @ITBA, along with a client application that allows the use of the additional protocol.

# Authors:

- [Catino, Kevin](https://github.com/Khato1319)
- [Chayer, Iván](https://github.com/ichayer)
- [Di Toro, Camila](https://github.com/camilaDiToro)
- [Mizrahi, Thomas](https://github.com/ThomasMiz)

# Build the binary files
```sh
user@user:/socks5-server$ make all
```
The binaries will be available inside the `bin` folder.

# Run the server and client

## Server

Run the server:
```sh
user@user:/socks5-server$ ./bin/socks5
```
> Note: `-h` flag shows help information and exits.

## Client:

First, it is essential to configure the environment variable `TOKEN` with a username and password to authenticate. The server stores users in a `users.txt` file, and when no users are found a default user "admin:admin" is created with administrator privileges.

Run the client:
```sh
user@user:/socks5-server$ export TOKEN="username:password"
```

After that, run the server:
```sh
user@user:/socks5-server$ ./bin/client
```
> Note: `-h` flag shows some execution information
