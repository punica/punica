# Punica
[![Build Status](https://travis-ci.com/punica/punica.svg?branch=master)](https://travis-ci.com/punica/punica) [![codecov.io](http://codecov.io/github/punica/punica/coverage.svg?branch=master)](http://codecov.io/github/punica/punica?branch=master)

## Introduction
Punica contains easy to use interface to the LwM2M server and client communication.

Detailed [Punica API documentation](./doc/PUNICA_API.md).

## Building
Punica follows [scripts to rule them all](https://github.com/github/scripts-to-rule-them-all) guidelines, therefore getting dependencies,
building and testing is implemented by executing scripts, however if you want,
you can read [manual project build instructions](./doc/MANUAL_BUILD.md).

1. Download [punica/punica](https://github.com/punica/punica):
```
$ git clone --recursive https://github.com/punica/punica.git
$ cd punica
```
_Note: If you already cloned Punica without initializing submodules, you can do so by executing:_
```
$ git submodule update --init --recursive
```

2. Build Punica by executing ```script/setup``` script, it will automatically
acquire and build required tools and dependencies, after that script will build Punica:
```
$ script/setup
```

_Note: If script succeeds, you should have binary file called `punica` in your `punica/build/` directory._

## Usage
You can get some details about `punica` by using `--help` or `-?` argument:
```
$ ./build/punica --help
Usage: punica [OPTION...]
Punica - interface to LwM2M server and all clients connected to it

  -c, --config=FILE          Specify parameters configuration file
  -l, --log=LOGGING_LEVEL    Specify logging level (0-5)
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```

You can get some details about `punica` usage by using `--usage` argument:
```
$ ./build/punica --usage
Usage: punica [-?V] [-c FILE] [-C CERTIFICATE] [-k PRIVATE_KEY]
            [-l LOGGING_LEVEL] [--config=FILE] [--certificate=CERTIFICATE]
            [--private_key=PRIVATE_KEY] [--log=LOGGING_LEVEL] [--help]
```

### Arguments list:
- `-c CONFIG_FILE` and `--config CONFIG_FILE` is used to load config file.

     Example of configuration file is in configuration section (below)

- `-d DATABASE_FILE` and `--database DATABASE_FILE` is used to load database file.

     Example and description of database file is in database section (below)

- `-k PRIVATE_KEY` and `--private_key PRIVATE_KEY` specify TLS security private key file.
  Private key could be generated with following command:
  ```
  $ openssl genrsa -out private.key 2048
  ```

- `-C CERTIFICATE` and `--certificate CERTIFICATE` specify TLS security certificate file.
  Certificate could be generated with following command (it requires private key file)
  ```
  $ openssl req -days 365 -new -x509 -key private.key -out certificate.pem
  ```

- `-l LOGGING_LEVEL` and `--log LOGGING_LEVEL` specify logging level from 0 to 5:

    `0: FATAL` - only very important messages are printed to console (usually the ones that inform about program malfunction).

    `1: ERROR` - important messages are printed to console (usually the ones that inform about service malfunction).

    `2: WARN` - warnings about possible malfunctions are reported.

    `3: INFO` - information about service actions (e.g., registration of new clients).

    `4: DEBUG` - more detailed information about service actions (e.g., detailed information about new clients).

    `5: TRACE` - very detailed information about program actions, including code tracing.

- `-V` and `--version` - print program version.

### Configuration file:
_Please note that configuration file is **OPTIONAL**! That means, that server will work properly without configuration file, however it wont be secure (no encryption nor authentication), therefore it is highly **RECOMMENDED** to configure server properly._

Example of configuration file:
```
{
  "http": {
    "port": 8888,
    "security": {
      "private_key": "private.key",
      "certificate": "certificate.pem",
      "jwt": {
        "secret_key": "some-very-secret-key",
        "algorithm": "HS512",
        "expiration_time": 3600,
        "users": [
          {
            "name": "admin",
            "secret": "not-same-as-name",
            "scope": [".*"]
          },
          {
            "name": "get-all",
            "secret": "lets-get",
            "scope": ["GET.*$"]
          },
          {
            "name": "one-device",
            "secret": "only-one-dev",
            "scope": [".* /endpoints/threeSeven/.*"]
          }
        ]
      }
    }
  },
  "coap": {
    "port": 5555,
    "database_file": "./database.json"
  },
  "logging": {
    "level": 5
  }
}
```

- **`http` settings section:**
  - `port` _(integer)_ - HTTP port to create socket on (is mentioned in arguments list). _**Optional**, default value is 8888._

  - **`security` settings subsection:**
    - ``private_key`` _(string)_ - TLS security private key file name (is mentioned in arguments list). _If you want to configure encryption, this option is **mandatory**._
    - ``certificate`` _(string)_ - TLS security certificate file name (is mentioned in arguments list). _If you want to configure encryption, this option is **mandatory**._
    - **`jwt` settings subsection (more about JWT could be found in [official website](https://jwt.io/)):**
      -  ``secret_key`` _(string)_ - Key which will be used in token signing and verification. _**Optional**, default value is randomly generated 32 bytes of data._
      -  ``algorithm`` _(string)_ - Signature encoding method. Valid values: ``"HS256"``, ``"HS384"``, ``"HS512"``, ``"RS256"``, ``"RS384"``, ``"RS512"``, ``"ES256"``, ``"ES384"``, ``"ES512"``. _**Optional**, default value is ``"HS512"``._
      -  ``expiration_time`` _(integer)_ - Seconds after which token is expired and wont be accepted anymore, default is `3600`. _**Optional**, default value is 3600._
      -  ``users``  _(list of objects)_ - List, which contains JWT authentication users. If no Users are specified, authentication wont work properly . _If you want to configure authentication, this option is **mandatory**._

         User object structure (more in [Punica API documentation](./doc/PUNICA_API.md)):
         - ``name`` _(string)_ - User name, which will be used on authentication process. _If you want to configure user authentication, this option is **mandatory**._
         - ``secret`` _(string)_ - User secret, which will be used on authentication process.  _If you want to configure user authentication, this option is **mandatory**._
         - ``scope`` _(list of strings)_ - User scope, which will be used on validating user request access, if user wont have required scope, it will get _Access Denied_.  _If you want to configure user authentication, this option is **optional**, however if scope is not specified, user will have access only to ``GET /version`` request._

         User scope should be **Regular expression pattern**, for example if you want user to have access to all GET requests , pattern should be `"GET .*"`, or if you would like user to have access to specific device manipulation: `".* /endpoints/threeSeven/.*"`, ultimate scope (all access) would be `".*"`.


- **`coap`**
  - `port` _(integer)_ - COAP port to create socket on (is mentioned in arguments list). _**Optional**, default value is 5555._
  - `database_file` _(string)_ - Location of database file on system. Can also be passed by command line arguments. _**Optional**, default value is NULL._

- **`logging`**
  - `level` _(integer)_ - visible messages logging level requirement (is mentioned in arguments list).  _**Optional**, default value is 2 (LOG_LEVEL_WARN)._

**database file**

Database file is used to store security credentials of devices managed by the server. The database file content is managed through /devices API (refer to API documentation in /doc project directory). If specified file does not exist, it will be created once security credentials are added. Not specifying a database file path will not disable secure communication between the server and the devices, but stored settings will not persist between run cycles.

Example of database file:
```
[
  {"uuid": "002c156d-2b18-4636-8fb0-3d3f371e100c", "name": "test-client-psk-1", "mode": "psk", "secret_key": "5ZjFwEd5QQC6FYABaWyxHg==", "public_key": "OEVEM0FFRTg4NDNC", "serial": ""},
  {"uuid": "53c5a0a9-8d4a-4acc-8dfd-2322d254944e", "name": "test-client-cert-1", "mode": "cert", "secret_key": "", "public_key": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJSekNCN3FBREFnRUNBaFJ6bldPWGZ0bHFZa0c0emozVkE2L0Z2VWhJTVRBSkJnY3Foa2pPUFFRQk1CUXgKRWpBUUJnTlZCQU1NQ1d4dlkyRnNhRzl6ZERBZUZ3MHhPVEF6TVRNd09EVTRORFJhRncweE9UQXpNVE13T1RVNApORFJhTUFBd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFSMUkzQTVqdEFGVzhxWFlUQVlteFg2CjdZRllqZHVJU2IxNWFSUDlpemYxVzBHaUFxMXZ3TkRZeVZTWTdURVViNFJPUHVEMjJWbVlBb3lpcXZsWXBBdDgKb3pNd01UQXZCZ05WSFJFRUtEQW1naVExTTJNMVlUQmhPUzA0WkRSaExUUmhZMk10T0dSbVpDMHlNekl5WkRJMQpORGswTkdVd0NRWUhLb1pJemowRUFRTkpBREJHQWlFQXByWm5ZZTBFVnlVMEdVa0hVYkFUMjBSZzFHb05Ecld5ClB2Qjk1U1FRNm5vQ0lRQ3BndnRjVnlXSkZ3NUpaaEdITXNPYm5Ld01hdnZtM0kzSlJaV0REalRyOEE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==", "serial": "c51jl37ZamJBuM491QOvxb1ISDE="},
  {"uuid": "698dc282-31d4-4b3c-9c0d-6bcca2526d81", "name": "test-client-none-1", "mode": "none", "secret_key": "", "public_key": "", "serial": ""}
]
```

The file consists of a json array of device entries, each specifying the following keys:

- **`uuid`** - a unique identifier used to specify a device entry.

- **`name`** - client name used in the CoAP/LWM2M layer.
  
- **`mode`** - device security credentials mode. `psk`, `cert` or `none`.

- **`secret_key`** - device pre-shared key or x509 private key. Base64 encoded.

- **`public_key`** - device pre-shared key id or x509 certificate. Base64 encoded.

- **`serial`** - client certificate serial number. Base64 encoded.

If an error exists in one of the entries, such as a wrong key type, invalid base64 string etc., the said entry will be ignored, but others will be used. The database file **MUST NOT** be edited during runtime.
