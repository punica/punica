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

2. Build `libwakaama` by following [punica/wakaama](https://github.com/punica/wakaama) instructions:
```
$ git clone https://github.com/punica/wakaama.git
$ wakaama/script/setup
$ cd wakaama/build
$ sudo make install
```

3. Install other required libraries from Github:
    - Install [`libulfius`](https://github.com/babelouest/ulfius):
    ```
    $ git clone https://github.com/babelouest/ulfius.git
    $ mkdir ulfius/build
    $ cd ulfius/build
    $ cmake ../
    $ sudo make install
    $ cd -
    ```
    
    - Install [`libjwt`](https://github.com/benmcollins/libjwt):
    ```
    $ git clone https://github.com/benmcollins/libjwt.git
    $ cd libjwt
    $ autoreconf -i
    $ ./configure
    $ make
    $ sudo make install
    $ cd -
    ```

4. Build PUNICA server
```
$ mkdir build
$ cd build/
$ cmake ../
$ make
```
After third step you should have binary file called `punica` in your `punica/build/` directory.

