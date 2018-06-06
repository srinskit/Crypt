/*
    Made with ❤ by srinSkit.
    Created on 28 May 2018.
*/

#ifndef CRYPT_CRYPT_H
#define CRYPT_CRYPT_H

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <map>
#include <fstream>
#include <sstream>

class Crypt {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    std::map<std::string, mbedtls_x509_crt *> certificates;
    // TODO: secure delete private key
    mbedtls_pk_context my_private_key;
public:
    bool initialize(const std::string &personalize);

    void terminate();

    // TODO: make more for other types of string
    void clear_string(std::string &buff);

    bool load_private_key(const std::string &path, const std::string &password);

    bool add_cert(const std::string &name, const char *path);

    void rem_cert(const std::string &name);

    // TODO: find better container for unsigned char[]
    bool encrypt(const std::string &msg, const std::string &certificate_name, std::string &dump);

    bool decrypt(const std::string &dump, std::string &msg);

    bool sign(const std::string &msg, std::string &dump);

    bool verify(const std::string &msg, const std::string &dump, const std::string &name);

    bool verify_cert(const std::string &root_name, const std::string &name);

    bool verify_cert(const std::string &root_name, const std::string &name, const std::string &common_name);
};

#endif //CRYPT_CRYPT_H