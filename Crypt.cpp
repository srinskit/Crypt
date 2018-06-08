/*
    Made with ❤ by srinSkit.
    Created on 28 May 2018.
*/

#include <mbedtls/net_sockets.h>
#include <mbedtls/aes.h>
#include "Crypt.h"

#define rccuc(x) (reinterpret_cast<const unsigned char *>(x))
#define rcuc(x) (reinterpret_cast<unsigned char *>(x))
#define rccc(x) (reinterpret_cast<const char *>(x))
#define rcc(x) (reinterpret_cast<char *>(x))

/*
 * Initialize libraries
 * return true on success, false on failure
 */
bool Crypt::initialize(const std::string &personalize) {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    auto ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, rccuc(personalize.c_str()),
                                     personalize.length());
    if (ret != 0) {
        mbedtls_printf(" [FAIL] CRYPT-INIT-1\n\n");
        return false;
    }
    return true;
}

/*
 * Cleanup
 */
void Crypt::terminate() {
    // delete all certificates
    for (auto &certificate : certificates) {
        mbedtls_x509_crt_free(certificate.second);
        delete (certificate.second);
    }
    for (auto &pair:aes_map)
        del_aes_key(pair.first);
    mbedtls_pk_free(&my_private_key);
    mbedtls_x509_crt_free(&my_cert);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}


/*
 * Clear string with null chars
 * TODO: find alternatives to store passwords in memory
 */
void Crypt::clear_string(std::string &buff) {
    for (char &i : buff)
        i = '\0';
}

/*
 * Load private key at 'path' using password 'password' into 'my_private_key'
 * return true on success, false on parse fail
 */
bool Crypt::load_private_key(const std::string &path, const std::string &password) {
    mbedtls_pk_init(&my_private_key);
    auto ret = mbedtls_pk_parse_keyfile(&my_private_key, path.c_str(), password.c_str());
    if (ret != 0) {
        mbedtls_printf(" [FAIL] mbedtls_pk_parse_keyfile returned -0x%04x\n\n", -ret);
        return false;
    }
    return true;
}

/*
 * Load certificate from 'path' and store it in map 'certificates' against 'name'
 * returns true on success, false if certificate of 'name' exists or file parse failed
 */
bool Crypt::add_cert(const std::string &name, const char *path) {
    if (certificates.find(name) != certificates.end())
        return false;
    auto certificate = new mbedtls_x509_crt;
    mbedtls_x509_crt_init(certificate);
    if (mbedtls_x509_crt_parse_file(certificate, path) != 0)
        return false;
    certificates[name] = certificate;
    return true;
}

/*
 * Remove certificate associated with 'name'
 */
void Crypt::rem_cert(const std::string &name) {
    auto cert = certificates[name];
    certificates.erase(name);
    mbedtls_x509_crt_free(cert);
    delete (cert);
}

/*
 * Encrypt 'msg' using public key in certificate associated with 'certificate_name'
 * and dump result into 'dump'
 * return true on success, false on encrypt failure
 */
bool Crypt::encrypt(const std::string &msg, const std::string &certificate_name, std::string &dump) {
    if (certificates.find(certificate_name) == certificates.end())
        return false;
    unsigned char result[MBEDTLS_MPI_MAX_SIZE];
    size_t olen = 0;
    auto ret = mbedtls_pk_encrypt(&certificates[certificate_name]->pk,
                                  rccuc(msg.c_str()), msg.length(), result, &olen,
                                  sizeof(result), mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        mbedtls_printf(" [FAIL] mbedtls_pk_encrypt returned -0x%04x\n\n", -ret);
        return false;
    }
    for (int i = 0; i < olen; ++i)
        dump.append(1, result[i]);
    return true;
}


/*
 * decrypts 'dump' using 'my_private_key' and restore it in 'msg'
 * returns true on success, false on failed decryption
 */
bool Crypt::decrypt(const std::string &dump, std::string &msg) {
    unsigned char result[MBEDTLS_MPI_MAX_SIZE];
    size_t olen = 0;
    auto ret = mbedtls_pk_decrypt(&my_private_key, rccuc(dump.c_str()), dump.length(),
                                  result, &olen, sizeof(result), mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        mbedtls_printf(" [FAIL] mbedtls_pk_decrypt returned -0x%04x\n\n", -ret);
        return false;
    }
    for (int i = 0; i < olen; ++i)
        msg.append(1, result[i]);
    return true;
}

/*
 * Dumps signed(using 'my_private_key') sha256 hash of 'msg' into 'dump'
 * returns true on success, false on signing failure
 */
bool Crypt::sign(const std::string &msg, std::string &dump) {
    unsigned char result[MBEDTLS_MPI_MAX_SIZE];
    unsigned char hash[32];
    size_t olen = 0;
    mbedtls_sha256(rccuc(msg.c_str()), msg.length(), hash, 0);
    auto ret = mbedtls_pk_sign(&my_private_key, MBEDTLS_MD_NONE, hash, sizeof(hash), result, &olen,
                               mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        mbedtls_printf(" [FAIL] mbedtls_pk_sign returned -0x%04x\n\n", -ret);
        return false;
    }
    for (int i = 0; i < olen; ++i)
        dump.append(1, result[i]);
    return true;
}

/*
 * Checks if 'dump' is equal to signed sha256 hash of 'msg' using certificate 'name'
 * returns true if sign is verified, false on failure
 */
bool Crypt::verify(const std::string &msg, const std::string &dump, const std::string &name) {
    if (certificates.find(name) == certificates.end())
        return false;
    unsigned char hash[32];
    mbedtls_sha256(rccuc(msg.c_str()), msg.length(), hash, 0);
    // TODO: check why verify seems to work with my_private_key too
    auto ret = mbedtls_pk_verify(&certificates[name]->pk, MBEDTLS_MD_NONE, hash, sizeof(hash),
                                 rccuc(dump.c_str()), dump.length());
    if (ret != 0) {
        mbedtls_printf(" [FAIL] mbedtls_pk_verify returned -0x%04x\n\n", -ret);
        return false;
    }
    return true;
}

/*
 * Verify certificate named 'name' using certificate named 'root' as CA
 * return true if verification successful, else false
 */
bool Crypt::verify_cert(const std::string &root, const std::string &name) {
    unsigned result;
    return mbedtls_x509_crt_verify(certificates[name], certificates[root], nullptr, nullptr, &result, nullptr,
                                   nullptr) ==
           0;
}

/*
 * Verify certificate named 'name' and its common name 'common_name'
 * using certificate named 'root' as CA
 * return true if verification successful, else false
 */
bool Crypt::verify_cert(const std::string &root, const std::string &name, const std::string &common_name) {
    unsigned result;
    return mbedtls_x509_crt_verify(certificates[name], certificates[root], nullptr, common_name.c_str(), &result,
                                   nullptr, nullptr) == 0;
}


bool Crypt::load_my_cert(const std::string &path, bool name_it_self) {
    if (name_it_self && certificates.find("self") != certificates.end())
        return false;
    mbedtls_x509_crt_init(&my_cert);
    if (mbedtls_x509_crt_parse_file(&my_cert, path.c_str()) != 0)
        return false;
    if (name_it_self) {
        auto certificate = new mbedtls_x509_crt;
        mbedtls_x509_crt_init(certificate);
        if (mbedtls_x509_crt_parse_file(certificate, path.c_str()) != 0) {
            return false;
        }
        certificates["self"] = certificate;
    }
    return true;
}


std::string Crypt::stringify_cert(const std::string &name) {
    if (certificates.find(name) == certificates.end())
        return nullptr;
    return std::string(rcc(certificates[name]->raw.p), certificates[name]->raw.len);
}


bool Crypt::certify_string(const std::string &buff, const std::string &common_name) {
    if (certificates.find(common_name) != certificates.end())
        return false;
    auto certificate = new mbedtls_x509_crt;
    mbedtls_x509_crt_init(certificate);
    if (mbedtls_x509_crt_parse(certificate, rccuc(buff.c_str()), buff.length()) ==
        0) {
        bool verified = false;
        for (auto &pair: certificates) {
            // Todo: check against only trusted sources
            uint32_t result;
            if (mbedtls_x509_crt_verify(certificate, pair.second, nullptr, common_name.c_str(), &result, nullptr,
                                        nullptr) == 0) {
                verified = true;
                break;
            }
        }
        if (verified) {
            certificates[common_name] = certificate;
            return true;
        }
    }
    delete (certificate);
    return false;
}

bool Crypt::gen_aes_key(std::string &key) {
    unsigned char buff[32];
    int ret;
    if ((ret = mbedtls_ctr_drbg_random(&ctr_drbg, buff, sizeof(buff))) != 0) {
        mbedtls_printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
        return false;
    }
    key.assign(rcc(buff), sizeof(buff));
    return true;
}

bool Crypt::save_aes_key(const std::string &name, const std::string &key) {
    auto aes_e = new mbedtls_aes_context;
    mbedtls_aes_init(aes_e);
    mbedtls_aes_setkey_enc(aes_e, rccuc(key.c_str()), 256);
    aes_map[name] = aes_e;
    return true;
}

bool Crypt::save_aes_key(const std::string &name) {
    std::string key;
    if (!gen_aes_key(key))return false;
    return save_aes_key(name, key);
}

bool Crypt::del_aes_key(const std::string &name) {
    auto aes_e = aes_map[name];
    mbedtls_aes_free(aes_e);
    aes_map.erase(name);
    delete aes_e;
    return true;
}

bool Crypt::encrypt_sym(const std::string &msg, const std::string &key_name, std::string &dump) {
    unsigned char output[2048];
    unsigned char iv[16];
    int ret;
    auto aes = aes_map[key_name];
    if ((ret = mbedtls_ctr_drbg_random(&ctr_drbg, iv, sizeof(iv))) != 0) {
        mbedtls_printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
        return false;
    }
    dump.assign(rcc(iv), sizeof(iv));
    if (mbedtls_aes_crypt_cfb8(aes, MBEDTLS_AES_ENCRYPT, msg.length(), iv, rccuc(msg.c_str()), output) != 0) {
        dump.clear();
        return false;
    }
    dump.append(rcc(output), msg.length());
    return true;
}

bool Crypt::decrypt_sym(const std::string &dump, const std::string &key_name, std::string &msg) {
    unsigned char output[2048];
    unsigned char iv[16];
    auto aes = aes_map[key_name];
    dump.copy(rcc(iv), sizeof(iv));
    auto enc_msg = dump.substr(sizeof(iv));
    if (mbedtls_aes_crypt_cfb8(aes, MBEDTLS_AES_DECRYPT, enc_msg.length(), iv, rccuc(enc_msg.c_str()), output) != 0) {
        return false;
    }
    msg.append(rcc(output), dump.length() - sizeof(iv));
    return true;
}


SecureSock::Server::Server(Crypt *crypt) {
    my_crypt = crypt;
}

bool SecureSock::Server::init() {
    mbedtls_net_init(&listen_fd);
    mbedtls_ssl_config_init(&conf);
    return true;
}

bool SecureSock::Server::bind(int port) {
    int ret;
    if ((ret = mbedtls_net_bind(&listen_fd, nullptr, std::to_string(port).c_str(), MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf(" [FAIL]  ! mbedtls_net_bind returned %d\n\n", ret);
        return false;
    }
    return true;
}


bool SecureSock::Server::listen() {
    int ret;
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" [FAIL]  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        return false;
    }
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &my_crypt->ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, nullptr, stdout);
    mbedtls_ssl_conf_ca_chain(&conf, my_crypt->my_cert.next, nullptr);
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &my_crypt->my_cert, &my_crypt->my_private_key)) != 0) {
        mbedtls_printf(" [FAIL]  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        return false;
    }
    return true;
}

int SecureSock::Server::accept() {
    int ret = 0;
    auto client = new SSClient;
    mbedtls_ssl_init(&client->ssl);
    mbedtls_net_init(&client->client_fd);
    if ((ret = mbedtls_ssl_setup(&client->ssl, &conf)) != 0) {
        mbedtls_printf(" [FAIL]  ! mbedtls_ssl_setup returned %d\n\n", ret);
    } else if ((ret = mbedtls_net_accept(&listen_fd, &client->client_fd, nullptr, 0, nullptr)) != 0) {
        mbedtls_printf(" [FAIL]  ! mbedtls_net_accept returned %d\n\n", ret);
    } else {
        mbedtls_ssl_set_bio(&client->ssl, &client->client_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);
        while ((ret = mbedtls_ssl_handshake(&client->ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                mbedtls_printf(" [FAIL]  ! mbedtls_ssl_handshake returned %d\n\n", ret);
                break;
            }
        }
    }
    if (ret != 0) {
        mbedtls_ssl_free(&client->ssl);
        mbedtls_net_free(&client->client_fd);
        delete (client);
        return -1;
    }
    sock_map[client->client_fd.fd] = client;
    return client->client_fd.fd;
}

ssize_t SecureSock::Server::read(int fd, std::string &msg, size_t count) {
    int ret = 0;
    auto client = sock_map[fd];
    unsigned char buf[count];
    memset(buf, 0, count);
    ret = mbedtls_ssl_read(&client->ssl, buf, count);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        return -1;
    if (ret <= 0) {
        switch (ret) {
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                mbedtls_printf(" connection was closed gracefully\n");
                return 0;

            case MBEDTLS_ERR_NET_CONN_RESET:
                mbedtls_printf(" connection was reset by peer\n");
                return 0;

            default:
                mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", -ret);
        }
        return ret == 0 ? 0 : -1;
    }
    msg.append(rcc(buf), static_cast<unsigned long>(ret));
    return ret;
}

ssize_t SecureSock::Server::write(int fd, const std::string &msg) {
    int ret;
    auto client = sock_map[fd];
    while ((ret = mbedtls_ssl_write(&client->ssl, rccuc(msg.c_str()),
                                    msg.length())) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" [FAIL]  ! peer closed the connection\n\n");
            return 0;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" [FAIL]  ! mbedtls_ssl_write returned %d\n\n", ret);
            return -1;
        }
    }
    return ret;
}

bool SecureSock::Server::close(int fd) {
    int ret;
    auto client = sock_map[fd];
    while ((ret = mbedtls_ssl_close_notify(&client->ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" [FAIL]  ! mbedtls_ssl_close_notify returned %d\n\n", ret);
            return false;
        }
    }
    mbedtls_ssl_free(&client->ssl);
    mbedtls_net_free(&client->client_fd);
    delete (client);
    sock_map.erase(fd);
    return true;
}

bool SecureSock::Server::close() {
    for (auto &pair:sock_map)
        close(pair.first);
    mbedtls_net_free(&listen_fd);
    mbedtls_ssl_config_free(&conf);
    return true;
}

bool SecureSock::Server::terminate() {
    return true;
}

SecureSock::Client::Client(Crypt *crypt) {
    my_crypt = crypt;
}

bool SecureSock::Client::init() {
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    return true;
}

bool SecureSock::Client::connect(const std::string &hostname, const std::string &server_name, int port,
                                 const std::string &ca_cert) {
    int ret = 0;
    auto cacert = *my_crypt->certificates[ca_cert];
    if ((ret = mbedtls_net_connect(&server_fd, server_name.c_str(), std::to_string(port).c_str(),
                                   MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf(" [FAIL]  ! mbedtls_net_connect returned %d\n\n", ret);
        close();
        return false;
    }
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" [FAIL]  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        close();
        return false;
    }
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &my_crypt->ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, nullptr, stdout);
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf(" [FAIL]  ! mbedtls_ssl_setup returned %d\n\n", ret);
        close();
        return false;
    }
    if ((ret = mbedtls_ssl_set_hostname(&ssl, hostname.c_str())) != 0) {
        mbedtls_printf(" [FAIL]  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        close();
        return false;
    }
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" [FAIL]  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
            close();
            return false;
        }
    }
    uint32_t flags;
    if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
        char vrfy_buf[512];
        mbedtls_printf(" [FAIL]");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        mbedtls_printf("%s\n", vrfy_buf);
        return false;
    }
    return true;
}

ssize_t SecureSock::Client::read(std::string &msg, size_t count) {
    int ret;
    unsigned char buf[count];
    memset(buf, 0, count);
    ret = mbedtls_ssl_read(&ssl, buf, count);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        return -1;
    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        return 0;
    if (ret < 0) {
        mbedtls_printf(" [FAIL]  ! mbedtls_ssl_read returned %d\n\n", ret);
        return -1;
    }
    if (ret == 0) {
        mbedtls_printf("\n\nEOF\n\n");
        return 0;
    }
    msg.append(rcc(buf), static_cast<unsigned long>(ret));
    return ret;
}

ssize_t SecureSock::Client::write(const std::string &msg) {
    int ret;
    while ((ret = mbedtls_ssl_write(&ssl, rccuc(msg.c_str()), msg.length())) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" [FAIL]  ! peer closed the connection\n\n");
            return 0;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" [FAIL]  ! mbedtls_ssl_write returned %d\n\n", ret);
            return -1;
        }
    }
    return ret;
}

bool SecureSock::Client::close() {
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    return true;
}

bool SecureSock::Client::terminate() {
    return false;
}

