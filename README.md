# Crypt
A simplified interface to common cryptography functions written on top of ARM's mbedtls. 

**The interface is not final and the library may not be safe.** I do not claim to use the best practices and the current work is just the foundation. Someone inexperienced(like me) will see the need for such a project. Any help is welcome. 

## Don't roll your own crypto, bro. 
Crypt does **not** implement cryptographic algorithms. It adds a layer of abstraction to well-established crypto libraries(only mbedtls as of now). Crypt exposes commonly used functionality in a not-so-_cryptic_ way. Crypt also provides key management so you do not have to worry about _losing_ them. 

Crypt uses safe defaults under the hood and exposes minimum control to the developer. It's not for everyone. It is for projects where crypto is not core, but is still **essential**.

### Aim
* Promote best practices: Crypto libraries provide lots of options. Crypt limits these to few safe options.
* Encourage devs: Crypt allows devs to build safe applications without much extra effort.
* Ease switching between crypto libraries: Switch to a library you believe in without replacing all 192 occurances of openssl.

## Install mbedtls
Install mbedtls (as shared libraries if applicable) as in it's [README](https://github.com/ARMmbed/mbedtls#compiling) or as below 
#### Using CMake
1. Download [source](https://github.com/ARMmbed/mbedtls)
2. Make directory _build_ inside the downloaded source
3. Inside _build_ run `cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On ..`
4. Inside _build_ run `make install` or `sudo make install`

## Install Crypt
#### Using CMake
1. Install mbedtls
2. Download [source](https://github.com/srinskit/Crypt)
3. Make directory _build_ inside the downloaded source
4. Inside _build_ run `cmake ..`
5. Inside _build_ run `make install` or `sudo make install`
