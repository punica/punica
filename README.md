# Punica

**Introduction**
----
Punica contains easy to use interface to the LwM2M server and client communication.

Detailed [Punica API documentation](./doc/PUNICA_API.md).

**Building**
----
Punica follows [scripts to rule them all](https://github.com/github/scripts-to-rule-them-all) guidelines, therefore getting dependencies,
building and testing is implemented by executing scripts, however if you want,
you can read [manual project build instructions](./doc/MANUAL_BUILD.md).

1. Build Punica by executing ```script/setup``` script, it will automatically
acquire and build required tools and dependencies, after that script will build Punica:

```
$ sudo script/setup
```

If script succeeds, you should have binary file called `punica` in your `punica/build/` directory.

**Usage**
----
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

**Arguments list:**
- `-c CONFIG_FILE` and `--config CONFIG_FILE` is used to load config file.

     Example of configuration file is in configuration section (below)

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

**configuration file**

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
    "port": 5555
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

- **`logging`**
  - `level` _(integer)_ - visible messages logging level requirement (is mentioned in arguments list).  _**Optional**, default value is 2 (LOG_LEVEL_WARN)._
