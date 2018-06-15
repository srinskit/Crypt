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
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/platform.h"
#include <cstring>
#include <cstdio>
#include <iostream>
#include <map>
#include <fstream>
#include <sstream>

namespace SecureSock {
    class Server;

    class Client;
}
class Crypt {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    std::map<std::string, mbedtls_x509_crt *> certificates;
    // TODO: secure delete private key
    mbedtls_pk_context my_private_key;
    mbedtls_x509_crt my_cert;
    std::map<std::string, mbedtls_aes_context *> aes_map;
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

    bool verify_cert(const std::string &root, const std::string &name);

    bool verify_cert(const std::string &root, const std::string &name, const std::string &common_name);

    bool load_my_cert(const std::string &path, bool name_it_self = false);

    std::string stringify_cert(const std::string &name);

    bool certify_string(const std::string &buff, const std::string &name);

    bool aes_gen_key(std::string &key);

    bool aes_save_key(const std::string &name, const std::string &key);

    bool aes_save_key(const std::string &name);

    bool aes_del_key(const std::string &name);

    bool aes_encrypt(const std::string &msg, const std::string &key_name, std::string &dump);

    bool aes_decrypt(const std::string &dump, const std::string &key_name, std::string &msg);

    friend class SecureSock::Server;

    friend class SecureSock::Client;
};


namespace SecureSock {
    class Server {
        Crypt *my_crypt;
        mbedtls_ssl_config conf;
        mbedtls_net_context listen_fd;
        struct SSClient {
            mbedtls_net_context client_fd;
            mbedtls_ssl_context ssl;
        };
        std::map<int, SSClient *> sock_map;
    public:
        explicit Server(Crypt *crypt);

        bool init();

        bool bind(int port);

        // Todo: mention how many in listen queue
        bool listen();

        int accept();

        // Todo: A support for multiple buffer length reads using ioctl
        ssize_t read(int fd, std::string &msg, size_t count = 2048);

        ssize_t write(int fd, const std::string &msg);

        bool close(int fd);

        bool close();

        bool terminate();
    };

    class Client {
        Crypt *my_crypt;
        mbedtls_ssl_config conf;
        mbedtls_ssl_context ssl;
        mbedtls_net_context server_fd;
    public:
        explicit Client(Crypt *crypt);

        bool init();

        bool connect(const std::string &hostname, const std::string &server_name, int port,
                     const std::string &ca_cert = "root");

        ssize_t read(std::string &msg, size_t count = 2048);

        ssize_t write(const std::string &msg);

        bool close();

        bool terminate();
    };
}


#endif //CRYPT_CRYPT_H