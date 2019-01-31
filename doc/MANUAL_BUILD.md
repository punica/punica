**Building Manually**
----
1. Download and install [punica/punica](https://github.com/punica/punica):
```
$ git clone --recursive git@github.com:punica/punica.git
$ cd punica
```
_Note: If you already cloned Punica without initializing submodules, you can do so by executing:_
    
```
$ git submodule update --init --recursive
```
2. Install required tools and libraries:
```
$ sudo apt-get update
$ sudo apt-get git-core cmake build-essential automake libtool gnutls-bin
$ sudo apt-get install libssl-dev libgnutls28-dev libmicrohttpd-dev
```

3.1. Build and install Jansson library (located in `third_party/jansson`). You can do so by following instructions at [akheron/jansson](https://github.com/akheron/jansson) repository.

3.2. Build and install JWT library (located in `third_party/libjwt`). You can do so by following instructions at [benmcollins/libjwt](https://github.com/benmcollins/libjwt) repository.

3.3. Build and install Curl library (located in `third_party/curl`). You can do so by following instructions at [curl/curl](https://github.com/curl/curl) repository.

3.4. Build and install Ulfius library (located in `third_party/ulfius`). You can do so by following instructions at [babelouest/ulfius](https://github.com/babelouest/ulfius) repository.

3.5. Build and install wakaama library (located in `third_party/wakaama`). You can do so by following [punica/wakaama](https://github.com/punica/wakaama) instructions.

4. Build Punica server

If you installed locally or want to build punica the easy way:
```
$ DO_NOT_BOOTSTRAP=true ./script/setup
```
or build manually (_Note: this method should work only for globally installed libraries._).
```
$ mkdir build
$ cd build/
$ cmake ../
$ make
```
After last step you should have binary file called `punica` in your `punica/build/` directory.

