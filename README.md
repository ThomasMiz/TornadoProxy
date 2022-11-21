<<<<<<< HEAD
# socks5v

Implementación de un proxy SOCKS5.

Desarrollado por:

- [Catino, Kevin](https://github.com/Khato1319)
- [Chayer, Iván](https://github.com/ichayer)
- [Di Toro, Camila](https://github.com/camilaDiToro)
- [Miz, Thomas](https://github.com/ThomasMiz)

## Compilacion & requisitos

### Requisitos
- Make
- GCC

### Compilacion

```make all```

> Se puede limpiar el proyecto con `make clean`

Se generarán dos binarios llamados `sock5v` y `client` dentro del directorio `bin` en la raíz. El primero corresponde al servidor proxy SOCKS 5, mientras que el segundo es un cliente que permite la comunicación con el servidor que corre en `sock5v` a través de un protocolo de monitoreo propietario.

## Ejecucion

### Servidor SOCKS5

Se debe correr el comando:

```./bin/socks5v [ARGS]```

Se puede obtener el detalle de los flags y argumentos posibles corriendo `./bin/socks5v -h`

### Cliente de monitoreo

El cliente extrae las credenciales de una variable de entorno de nombre `TOKEN`. La misma debe contener el formato `<user>:<password>`. Si quisiéramos autenticarnos con el usuario "user" que tiene la contraseña "1234" podríamos correr el siguiente comando previo a la ejecución del cliente:
```export TOKEN="user1:1234" ```
Luego, para ejecutar el cliente, se debe correr el comando:

```./bin/client <command> [ARGS]```

Se pueden consultar los posibles comandos y sus argumentos corriendo `./bin/client -h`
||||||| parent of ef028f6 (Update README.md)
# TornadoProxy
=======
# Socks5 Server

The developed application is a proxy server that implements the SOCKSv5 protocol [[RFC1928]](https://www.rfc-editor.org/rfc/rfc1928 "[RFC1928]") and its associated functionalities with an additional protocol that allows managing and obtaining relevant information from the server. The proxy supports a series of requirements dictated by the chair of [72.07] - Communication Protocols @ITBA, along with a client application that allows the use of the additional protocol.

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
> Note: `-h` flag shows help information and exists.

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
>>>>>>> ef028f6 (Update README.md)
