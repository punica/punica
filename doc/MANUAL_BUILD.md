## Building Manually

1. Download [punica/punica](https://github.com/punica/punica):
```
$ git clone --recursive https://github.com/punica/punica.git
$ cd punica
```
_Note: If you already cloned Punica without initializing submodules, you can do so by executing:_
```
$ git submodule update --init --recursive
```
2. Install required tools and libraries (example is for debian based distributions):
```
$ sudo apt-get update
$ sudo apt-get install git-core cmake build-essential automake libtool gnutls-bin
$ sudo apt-get install libssl-dev libgnutls28-dev libmicrohttpd-dev
```

3.1. Build and install Jansson library (located in `third_party/jansson`). You can do so by following instructions:
```
$ rm -rf third_party/jansson/build
$ mkdir third_party/jansson/build
$ cd third_party/jansson/build
$ cmake ../ -DJANSSON_WITHOUT_TESTS=on -DJANSSON_BUILD_DOCS=off -DJANSSON_EXAMPLES=off -DJANSSON_BUILD_MAN=off
$ make clean
$ make
$ sudo make install
$ cd -
```
_Note: alternatively you can follow   [akheron/jansson](https://github.com/akheron/jansson) repository instructions._

3.2. Build and install JWT library (located in `third_party/libjwt`). You can do so by following instructions:
```
$ cd third_party/libjwt
$ autoreconf -i
$ ./configure --disable-doxygen-doc --enable-static=yes
$ make clean
$ make
$ sudo make install
$ cd -
```
_Note: alternatively you can follow  [benmcollins/libjwt](https://github.com/benmcollins/libjwt) repository instructions._

3.3. Build and install Curl library (located in `third_party/curl`). You can do so by following instructions:
```
$ cd third_party/curl
$ ./buildconf
$ ./configure --without-ssl --with-gnutls --disable-ares --disable-proxy --disable-verbose --without-libidn2 --without-librtmp --disable-ldap --disable-manual --enable-static=yes
$ make clean
$ make
$ sudo make install
$ cd -
```
_Note: alternatively you can follow [curl/curl](https://github.com/curl/curl) repository instructions._

3.4. Build and install Ulfius library (located in `third_party/ulfius`). You can do so by following instructions:
```
$ rm -rf third_party/ulfius/build
$ mkdir third_party/ulfius/build
$ cd third_party/ulfius/build
$ cmake ../ -DWITH_YDER=off -DBUILD_UWSC=off -DWITH_GNUTLS=on -DWITH_CURL=on -DBUILD_STATIC=on
$ make clean
$ make
$ sudo make install
$ cd -
```
_Note: alternatively you can follow [babelouest/ulfius](https://github.com/babelouest/ulfius) repository instructions._

3.5. Build and install wakaama library (located in `third_party/wakaama`). You can do so by following instructions:
```
$ git clone https://github.com/punica/wakaama.git
$ wakaama/script/setup
$ cd wakaama/build
$ sudo make install
```
_Note: alternatively you can follow [punica/wakaama](https://github.com/punica/wakaama) repository instructions._

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
$ make clean
$ make
```
After last step you should have binary file called `punica` in your `punica/build/` directory.

