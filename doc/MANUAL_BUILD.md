**Building Manually**
----
1. Download and install [punica/punica](https://github.com/punica/punica):
```
$ git clone --recursive git@github.com:punica/punica.git
punica $ cd punica
```
_Note: If you already cloned Punica without initializing submodules, you can do so by executing:_
    
```
punica $ git submodule update --init --recursive
```

2. Build libwakaama by following [punica/wakaama](https://github.com/punica/wakaama) instructions.

3. Install other required libraries from Github:
```
punica $ git clone --recursive https://github.com/babelouest/ulfius.git
punica $ cd ulfius/lib/orcania
punica/ulfius/lib/orcania $ make && sudo make install
punica/ulfius/lib/orcania $ cd ../yder
punica/ulfius/lib/yder $ make && sudo make install
punica/ulfius/lib/yder $ cd ../..
punica/ulfius $ make
punica/ulfius $ sudo make install
punica $ cd ..
punica $ git clone https://github.com/benmcollins/libjwt
punica $ cd libjwt
punica/libjwt $ autoreconf -i
punica/libjwt $ ./configure
punica/libjwt $ make
punica/libjwt $ sudo make install
punica/libjwt $ cd ..
```

3. Build PUNICA server
```
punica $ mkdir build
punica $ cd build/
punica/build $ cmake ../
punica/make $ make
```
After third step you should have binary file called `punica` in your `punica/build/` directory.

