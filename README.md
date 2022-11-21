[![en](https://img.shields.io/badge/lang-en-red.svg)](https://github.com/ThomasMiz/socks5-server/blob/main/README.en.md)
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
