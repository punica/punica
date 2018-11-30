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

2. Build libwakaama by following [punica/wakaama](https://github.com/punica/wakaama) instructions.

3. Install other required libraries from Github:
```
$ git clone --recursive https://github.com/babelouest/ulfius.git
$ cd ulfius/lib/orcania
$ make && sudo make install
$ cd ../yder
$ make && sudo make install
$ cd ../..
$ make
$ sudo make install
$ cd ..
$ git clone https://github.com/benmcollins/libjwt
$ autoreconf -i
$ ./configure
$ make
$ sudo make install
$ cd ..
```

3. Build PUNICA server
```
$ mkdir build
$ cd build/
$ cmake ../
$ make
```
After third step you should have binary file called `punica` in your `punica/build/` directory.

