/*
    Made with ❤ by srinSkit.
    Created on 28 May 2018.
*/

#ifndef CRYPT_CRYPT_H
#define CRYPT_CRYPT_H

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/aes.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include "mbedtls/debug.h"
#include <cstring>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <vector>

#define rccuc(x) (reinterpret_cast<const unsigned char *>(x))
#define rcuc(x) (reinterpret_cast<unsigned char *>(x))
#define rccc(x) (reinterpret_cast<const char *>(x))
#define rcc(x) (reinterpret_cast<char *>(x))
typedef const std::string &cs;
typedef std::string &s;

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
    std::map<std::string, mbedtls_aes_context *> aes_context_map;
    std::map<std::string, std::string> aes_key_map;
    unsigned char aes_iv[16];
    char error_buff[1024];
    bool print_errors;

    void print_internal_error(int ret);

public:
    Crypt() = default;

    bool initialize(cs personalize, bool print_errors = false);

    void terminate();

    // TODO: make more for other types of string
    void clear_string(s buff);

    bool load_my_key(cs path, cs password);

    bool load_my_cert(cs path, cs next = "", bool name_it_self = false);

    bool add_cert(cs name, cs path, cs next = "");

    void rem_cert(cs name);

    // TODO: find better container for unsigned char[]
    bool encrypt(cs msg, cs certificate_name, s dump);

    bool decrypt(cs dump, s msg);

    bool sign(cs msg, s dump);

    bool verify_sign(cs msg, cs dump, cs name);

    bool checksum(cs msg, s sum);

    bool verify_checksum(cs msg, cs sum);

    int checksum_size();

    bool verify_cert(cs root, cs name);

    bool verify_cert(cs root, cs name, cs common_name);

    std::string stringify_cert(cs name);

    bool certify_string(cs buff, cs name);

    bool aes_gen_key(s key);

    bool aes_save_key(cs name, cs key);

    bool aes_save_key(cs name);

    bool aes_del_key(cs name);

    bool aes_encrypt(cs msg, cs key_name, s dump);

    bool aes_decrypt(cs dump, cs key_name, s msg);

    bool aes_exist_key(cs name);

    bool aes_get_key(cs name, s key);

    bool bytes_to_hex(cs bytes, s hex);

    bool hex_to_bytes(cs hex, s bytes);

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
        bool listen(cs ca_cert, bool require_client_auth = false);

        int accept();

        // Todo: A support for multiple buffer length reads using ioctl
        ssize_t read(int fd, s msg, size_t count = 2048);

        ssize_t write(int fd, cs msg);

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

        bool connect(cs hostname, cs server_name, int port,
                     cs ca_cert = "root", bool require_client_auth = false);

        ssize_t read(s msg, size_t count = 2048);

        ssize_t write(cs msg);

        bool close();

        bool terminate();
    };
}


#endif //CRYPT_CRYPT_H