# Crypt
A simple interface to common cryptography functions on top of ARM's mbedtls.

## Install mbedtls
Install mbedtls (as shared libraries if applicable) as in it's [README](https://github.com/ARMmbed/mbedtls#compiling) or as below 
#### Using CMake
1. Download [source](https://github.com/ARMmbed/mbedtls)
2. Make directory _build_ inside the downloaded source
3. Inside _build_ run `cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On ..`
4. Inside _build_ run `make install` or `sudo make install`

## Install Crypt
#### Using CMake
1. Download [source](https://github.com/srinskit/Crypt)
2. Make directory _build_ inside the downloaded source
3. Inside _build_ run `cmake ..`
4. Inside _build_ run `make install` or `sudo make install`
