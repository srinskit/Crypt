/*
    Made with ❤ by srinSkit.
    Created on 28 May 2018.
*/

#include "Crypt.h"

#define print_err if(print_errors) printf
#define print_err1 if(my_crypt->print_errors) printf
// Use macro carefully

/*
 * Initialize libraries
 * return true on success, false on Crypture
 */
bool Crypt::initialize(cs personalize, bool print_errors) {
    this->print_errors = print_errors;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    auto ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, rccuc(personalize.c_str()),
                                     personalize.length());
    if (ret != 0) {
        print_err("[Crypt] mbedtls_ctr_drbg_seed returned -0x%04x\n", ret);
        return false;
    }
    if ((ret = mbedtls_ctr_drbg_random(&ctr_drbg, aes_iv, sizeof(aes_iv))) != 0) {
        print_err("[Crypt] mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
        return false;
    }
    mbedtls_x509_crt_init(&my_cert);
    mbedtls_pk_init(&my_private_key);
    return true;
}

/*
 * Cleanup
 */
void Crypt::terminate() {
    // Unchain before free
    for (auto &certificate : certificates)
        certificate.second->next = nullptr;
    my_cert.next = nullptr;
    // Free
    for (auto &certificate : certificates) {
        mbedtls_x509_crt_free(certificate.second);
        delete (certificate.second);
    }
    for (auto &pair:aes_context_map) {
        mbedtls_aes_free(pair.second);
        delete (pair.second);
    }
    mbedtls_pk_free(&my_private_key);
    mbedtls_x509_crt_free(&my_cert);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}


/*
 * Clear string with null chars
 * TODO: find alternatives to store passwords in memory
 */
void Crypt::clear_string(s buff) {
    for (char &i : buff)
        i = '\0';
}

/*
 * Load private key at 'path' using password 'password' into 'my_private_key'
 * return true on success, false on parse Crypt
 */
bool Crypt::load_my_key(cs path, cs password) {
    mbedtls_pk_free(&my_private_key);
    mbedtls_pk_init(&my_private_key);
    auto ret = mbedtls_pk_parse_keyfile(&my_private_key, path.c_str(), password.c_str());
    if (ret != 0) {
        print_err("[Crypt] mbedtls_pk_parse_keyfile returned -0x%04x\n", -ret);
        return false;
    }
    return true;
}

/*
 *
 */
bool Crypt::load_my_cert(cs path, cs next, bool name_it_self) {
    if (name_it_self && certificates.find("self") != certificates.end()) {
        print_err("[Crypt] certificate tagged self already exists\n");
        return false;
    }
    mbedtls_x509_crt_free(&my_cert);
    mbedtls_x509_crt_init(&my_cert);
    int ret;
    if ((ret = mbedtls_x509_crt_parse_file(&my_cert, path.c_str())) != 0) {
        print_err("[Crypt] mbedtls_x509_crt_parse_file returned -0x%04x\n", -ret);
        return false;
    }
    if (next.length() != 0)
        my_cert.next = certificates[next];
    if (name_it_self)
        return add_cert("self", path, next);
    return true;
}

/*
 * Load certificate from 'path' and store it in map 'certificates' against 'name'
 * returns true on success, false if certificate of 'name' exists or file parse Crypted
 */
bool Crypt::add_cert(cs name, cs path, cs next) {
    if (certificates.find(name) != certificates.end()) {
        print_err("[Crypt] certificate tag taken\n");
        return false;
    }
    auto certificate = new mbedtls_x509_crt;
    mbedtls_x509_crt_init(certificate);
    int ret;
    if ((ret = mbedtls_x509_crt_parse_file(certificate, path.c_str())) != 0) {
        print_err("[Crypt] mbedtls_x509_crt_parse_file returned -0x%04x\n", -ret);
        return false;
    }
    certificates[name] = certificate;
    if (next.length() != 0) {
        auto it_next = certificates.find(next);
        if (it_next == certificates.end()) {
            print_err("[Crypt] next certificate tag not found\n");
            return false;
        }
        certificate->next = it_next->second;
    }
    return true;
}

/*
 * Remove certificate associated with 'name'
 */
void Crypt::rem_cert(cs name) {
    auto cert = certificates[name];
    certificates.erase(name);
    // Unchain before free
    cert->next = nullptr;
    mbedtls_x509_crt_free(cert);
    delete (cert);
}

/*
 * Encrypt 'msg' using public key in certificate associated with 'certificate_name'
 * and dump result into 'dump'
 * return true on success, false on encrypt Crypture
 */
bool Crypt::encrypt(cs msg, cs certificate_name, s dump) {
    if (certificates.find(certificate_name) == certificates.end()) {
        print_err("[Crypt] certificate not found\n");
        return false;
    }
    unsigned char result[MBEDTLS_MPI_MAX_SIZE];
    // Todo: check if enc msg can fit in 'result'
    size_t olen = 0;
    auto ret = mbedtls_pk_encrypt(&certificates[certificate_name]->pk,
                                  rccuc(msg.c_str()), msg.length(), result, &olen,
                                  sizeof(result), mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        print_err("[Crypt] mbedtls_pk_encrypt returned -0x%04x\n", -ret);
        return false;
    }
    dump.append(rcc(result), olen);
    return true;
}


/*
 * decrypts 'dump' using 'my_private_key' and restore it in 'msg'
 * returns true on success, false on Crypted decryption
 */
bool Crypt::decrypt(cs dump, s msg) {
    unsigned char result[MBEDTLS_MPI_MAX_SIZE];
    // Todo: check if enc msg can fit in 'result'
    size_t olen = 0;
    auto ret = mbedtls_pk_decrypt(&my_private_key, rccuc(dump.c_str()), dump.length(),
                                  result, &olen, sizeof(result), mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        print_err("[Crypt] mbedtls_pk_decrypt returned -0x%04x\n", -ret);
        return false;
    }
    msg.append(rcc(result), olen);
    return true;
}

/*
 * Dumps signed(using 'my_private_key') sha256 hash of 'msg' into 'dump'
 * returns true on success, false on signing Crypture
 */
bool Crypt::sign(cs msg, s dump) {
    unsigned char result[MBEDTLS_MPI_MAX_SIZE];
    // Todo: check if dec msg can fit in 'result'
    unsigned char hash[256 / 8];
    size_t olen = 0;
    mbedtls_sha256(rccuc(msg.c_str()), msg.length(), hash, 0);
    auto ret = mbedtls_pk_sign(&my_private_key, MBEDTLS_MD_SHA256, hash, 0, result, &olen, mbedtls_ctr_drbg_random,
                               &ctr_drbg);
    if (ret != 0) {
        print_err("[Crypt] mbedtls_pk_sign returned -0x%04x\n", -ret);
        return false;
    }
    dump.append(rcc(result), olen);
    return true;
}

/*
 * Checks if 'dump' is equal to signed sha256 hash of 'msg' using certificate 'name'
 * returns true if sign is verified, false on Crypture
 */
bool Crypt::verify_sign(cs msg, cs dump, cs name) {
    if (certificates.find(name) == certificates.end())
        return false;
    unsigned char hash[256 / 8];
    mbedtls_sha256(rccuc(msg.c_str()), msg.length(), hash, 0);
    // TODO: check if verify returns true if 'signed' using public key as it returns true when verified using pub/private key 
    auto ret = mbedtls_pk_verify(&certificates[name]->pk, MBEDTLS_MD_SHA256, hash, 0, rccuc(dump.c_str()),
                                 dump.length());
    if (ret != 0) {
        print_err("[Crypt] mbedtls_pk_verify returned -0x%04x\n", -ret);
        return false;
    }
    return true;
}

/*
 * Copy the SHA256 checksum of 'msg' into 'sum'
 * returns true always
 */
bool Crypt::checksum(cs msg, s sum) {
    unsigned char u_hash[256 / 8];
    mbedtls_sha256(rccuc(msg.c_str()), msg.length(), u_hash, 0);
    sum.assign(rcc(u_hash), sizeof(u_hash));
    return true;
}

/*
 * Verify if 'sum' is the SHA256 checksum of 'msg'
 * returns true on successful verification, else false
 */
bool Crypt::verify_checksum(cs msg, cs sum) {
    unsigned char u_hash[256 / 8];
    if (sum.length() != sizeof(u_hash)) return false;
    mbedtls_sha256(rccuc(msg.c_str()), msg.length(), u_hash, 0);
    return sum.compare(0, sum.length(), reinterpret_cast<const char *>(u_hash), sizeof(u_hash)) == 0;
}

/*
 * Get the size of a SHA256 checksum
 * returns the size of a SHA256 checksum
 */
int Crypt::checksum_size() {
    return 256 / 8;
}

/*
 * Verify certificate named 'name' using certificate named 'root' as CA
 * return true if verification successful, else false
 */
bool Crypt::verify_cert(cs root, cs name) {
    auto it_root = certificates.find(root), it_name = certificates.find(name);
    if (it_root == certificates.end() || it_name == certificates.end()) {
        perror("[Crypt] cannot resolve tag(s)\n");
        return false;
    }
    unsigned result;
    return mbedtls_x509_crt_verify(it_name->second, it_root->second, nullptr, nullptr, &result, nullptr, nullptr) == 0;
}

/*
 * Verify certificate named 'name' and its common name 'common_name'
 * using certificate named 'root' as CA
 * return true if verification successful, else false
 */
bool Crypt::verify_cert(cs root, cs name, cs common_name) {
    auto it_root = certificates.find(root), it_name = certificates.find(name);
    if (it_root == certificates.end() || it_name == certificates.end()) {
        perror("[Crypt] cannot resolve tag(s)\n");
        return false;
    }
    unsigned result;
    return mbedtls_x509_crt_verify(it_name->second, it_root->second, nullptr, common_name.c_str(), &result, nullptr,
                                   nullptr) == 0;
}


std::string Crypt::stringify_cert(cs name) {
    if (certificates.find(name) == certificates.end())
        return "";
    return std::string(rcc(certificates[name]->raw.p), certificates[name]->raw.len);
}


bool Crypt::certify_string(cs buff, cs common_name) {
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

/*
 * Generate a 256 bit AES key and store in into 'key'
 * return true on success, false on Crypture
 */
bool Crypt::aes_gen_key(s key) {
    unsigned char buff[32];
    int ret;
    if ((ret = mbedtls_ctr_drbg_random(&ctr_drbg, buff, sizeof(buff))) != 0) {
        print_err("[Crypt] mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
        return false;
    }
    key.assign(rcc(buff), sizeof(buff));
    return true;
}

/*
 * Save the AES key 'key' such that it can be addressable by 'name'
 * Save the key in a name-vs-key map (to enable raw access)
 * Initialize and save the name-vs-aes_context map
 * return true on success, false on Crypture
 * Todo: global keys not thread-safe
 */
bool Crypt::aes_save_key(cs name, cs key) {
    auto aes_e = new mbedtls_aes_context;
    mbedtls_aes_init(aes_e);
    int ret;
    if ((ret = mbedtls_aes_setkey_enc(aes_e, rccuc(key.c_str()), 256)) != 0) {
        mbedtls_aes_free(aes_e);
        delete (aes_e);
        print_err("[Crypt] mbedtls_aes_setkey_enc returned -0x%04x\n", -ret);
        return false;
    }
    aes_context_map[name] = aes_e;
    aes_key_map[name] = key;
    return true;
}

/*
 * Generate a 256 bit AES key that can be addressed by 'name'
 * return true on success, false on Crypture
 */
bool Crypt::aes_save_key(cs name) {
    std::string key;
    if (!aes_gen_key(key))return false;
    return aes_save_key(name, key);
}

/*
 * Delete key addressed by 'name'
 * Free the referenced aes_context erase map records
 * return true on success, false if 'name' was not found
 * Todo: global keys not thread-safe
 */
bool Crypt::aes_del_key(cs name) {
    if (aes_key_map.find(name) == aes_key_map.end()) {
        perror("[Crypt] cannot resolve tag\n");
        return false;
    }
    auto aes_e = aes_context_map[name];
    mbedtls_aes_free(aes_e);
    aes_context_map.erase(name);
    aes_key_map.erase(name);
    delete aes_e;
    return true;
}

/*
 * Encrypt 'msg' using AES key referred to by 'key_name' and assign the result to 'dump'
 * Mind the max message size of 2048(buff) - 16(IV)  bytes
 * return true on success, false if 'key_name' was not found, 'msg' too big
 * or encryption Crypture
 * Todo: fix conservative assumption: output.len = IV.len + msg.len.
 * Todo: common IV and global keys not thread-safe, fix return true if key is wrong too
 */
bool Crypt::aes_encrypt(cs msg, cs key_name, s dump) {
    unsigned char output[2048];
    if (msg.length() > (sizeof(output) - sizeof(aes_iv))) {
        perror("[Crypt] msg too large\n");
        return false;
    }
    auto it = aes_context_map.find(key_name);
    if (it == aes_context_map.end()) {
        perror("[Crypt] cannot resolve tag\n");
        return false;
    }
    auto aes = it->second;
    dump.assign(rcc(aes_iv), sizeof(aes_iv));
    int ret;
    if ((ret = mbedtls_aes_crypt_cfb8(aes, MBEDTLS_AES_ENCRYPT, msg.length(), aes_iv, rccuc(msg.c_str()), output)) !=
        0) {
        print_err("[Crypt] mbedtls_aes_crypt_cfb8 returned -0x%04x\n", -ret);
        dump.clear();
        return false;
    }
    dump.append(rcc(output), msg.length());
    return true;
}

/*
 * Decrypt 'dump' using AES key referred to by 'key_name' and append result to 'msg'
 * Mind the max dump size of 2048(buff) + 16(IV)  bytes
 * return true on success, false if 'key_name' not found, 'dump' too big or too small
 * or decryption Crypture
 * Todo: confirm encryption assumptions, make max decrypt dump size = max encrypt dump size
 * Todo: global keys not thread-safe
 */
bool Crypt::aes_decrypt(cs dump, cs key_name, s msg) {
    unsigned char output[2048];
    unsigned char iv[16];
    auto msg_size = dump.length() - sizeof(iv);
    if (msg_size > sizeof(output)) {
        perror("[Crypt] msg too large\n");
        return false;
    }
    auto it = aes_context_map.find(key_name);
    if (it == aes_context_map.end()) {
        perror("[Crypt] cannot resolve tag\n");
        return false;
    }
    auto aes = it->second;
    if (dump.copy(rcc(iv), sizeof(iv)) != sizeof(iv)) return false;
    auto enc_msg = dump.substr(sizeof(iv));
    int ret;
    if ((ret = mbedtls_aes_crypt_cfb8(aes, MBEDTLS_AES_DECRYPT, enc_msg.length(), iv, rccuc(enc_msg.c_str()),
                                      output)) != 0) {
        print_err("[Crypt] mbedtls_aes_crypt_cfb8 returned -0x%04x\n", -ret);
        return false;
    }
    msg.append(rcc(output), msg_size);
    return true;
}

/*
 * Check if a AES key tagged 'name' exists
 * return true if exists, else false
 */
bool Crypt::aes_exist_key(cs name) {
    return aes_key_map.find(name) != aes_key_map.end();
}

/*
 * Copies AES key tagged 'name' into 'key'
 * returns true if such a key exists, else false
 */
bool Crypt::aes_get_key(cs name, s key) {
    auto it = aes_key_map.find(name);
    if (it == aes_key_map.end())
        return false;
    key = it->second;
    return true;
}

/*
 * Print error message given mbedtls error code
 * For internal use
 */
void Crypt::print_internal_error(int err_code) {
    mbedtls_strerror(err_code, error_buff, sizeof(error_buff));
    print_err("%s\n", error_buff);
}

/*
 * Convert a string of bytes into a hex string
 * returns true if conversion was successful, else false
 */
bool Crypt::bytes_to_hex(cs bytes, s hex) {
    auto n_to_h = [](int x) {
        if (x < 10) return static_cast<char>('0' + x);
        if (x < 16) return static_cast<char>(x - 10 + 'a');
        return '0';
    };
    for (auto &ch:bytes) {
        hex.append(1, n_to_h((static_cast<unsigned char>(ch) / 16) % 16));
        hex.append(1, n_to_h(static_cast<unsigned char>(ch) % 16));
    }
    return true;
}

/*
 * Convert a hex string into a string of bytes
 * returns true if conversion was successful, else false
 */
bool Crypt::hex_to_bytes(cs hex, s bytes) {
    auto h_to_d = [](char x) {
        if (x >= '0' && x <= '9') return static_cast<unsigned char>(x - '0');
        return static_cast<unsigned char>(x - 'a' + 10);
    };
    if (hex.length() % 2) return false;
    int i = 0, byte;
    while (i < hex.length()) {
        byte = 16 * h_to_d(hex[i]) + h_to_d(hex[i + 1]);
        if (byte < 0 || byte > 255)
            return false;
        bytes.append(1, byte);
        i += 2;
    }
    return true;
}


/*
 * Pass as debug callback to supported mbedtls functions for debug info on stdout
 * For internal use
 */
void my_debug(void *ctx, int level, const char *file, int line,
              const char *str) {
    return;
    const char *p, *basename;
    (void) ctx;

/* Extract basename from file */
    for (p = basename = file; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\') {
            basename = p + 1;
        }
    }

    printf("%s:%04d: |%d| %s", basename, line, level, str);
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
        print_err1("[Crypt]  mbedtls_net_bind returned %d\n", ret);
        return false;
    }
    return true;
}

bool SecureSock::Server::listen(cs ca_cert, bool require_client_auth) {
    int ret;
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        print_err1("[Crypt]  mbedtls_ssl_config_defaults returned %d\n", ret);
        return false;
    }
    if (require_client_auth) {
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&conf, my_crypt->certificates[ca_cert], nullptr);
    } else {
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    }
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &my_crypt->ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, nullptr);
    mbedtls_debug_set_threshold(4);
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &my_crypt->my_cert, &my_crypt->my_private_key)) != 0) {
        print_err1("[Crypt]  mbedtls_ssl_conf_own_cert returned %d\n", ret);
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
        print_err1("[Crypt]  mbedtls_ssl_setup returned %d\n", ret);
    } else if ((ret = mbedtls_net_accept(&listen_fd, &client->client_fd, nullptr, 0, nullptr)) != 0) {
        print_err1("[Crypt]  mbedtls_net_accept returned %d\n", ret);
    } else {
        mbedtls_ssl_set_bio(&client->ssl, &client->client_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);
        while ((ret = mbedtls_ssl_handshake(&client->ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                print_err1("[Crypt]  mbedtls_ssl_handshake returned %d\n", ret);
                my_crypt->print_internal_error(ret);
                break;
            }
        }
// Todo: Confirm if looping is a threat
//        if ((ret = mbedtls_ssl_handshake(&client->ssl)) != 0) {
//            print_err1("[Crypt]  mbedtls_ssl_handshake returned %d\n", ret);
//            my_crypt->print_internal_error(ret);
//        }
        uint32_t flags;
        if ((flags = mbedtls_ssl_get_verify_result(&client->ssl)) != 0) {
            char vrfy_buf[512];
            print_err1("[Crypt]");
            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ", flags);
            print_err1("%s\n", vrfy_buf);
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

ssize_t SecureSock::Server::read(int fd, s msg, size_t count) {
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
                print_err1(" connection was closed gracefully\n");
                return 0;

            case MBEDTLS_ERR_NET_CONN_RESET:
                print_err1(" connection was reset by peer\n");
                return 0;

            default:
                print_err1(" mbedtls_ssl_read returned -0x%x\n", -ret);
        }
        return ret == 0 ? 0 : -1;
    }
    msg.append(rcc(buf), static_cast<unsigned long>(ret));
    return ret;
}

ssize_t SecureSock::Server::write(int fd, cs msg) {
    int ret;
    auto client = sock_map[fd];
// Todo: confirm if looping is a threat
    while ((ret = mbedtls_ssl_write(&client->ssl, rccuc(msg.c_str()),
                                    msg.length())) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            print_err1("[Crypt]  peer closed the connection\n");
            return 0;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            print_err1("[Crypt]  mbedtls_ssl_write returned %d\n", ret);
            return -1;
        }
    }
    return ret;
}

bool SecureSock::Server::close(int fd) {
    auto it = sock_map.find(fd);
    if (it == sock_map.end()) return false;
    int ret;
    auto client = it->second;
    while ((ret = mbedtls_ssl_close_notify(&client->ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            print_err1("[Crypt]  mbedtls_ssl_close_notify returned %d\n", ret);
            return false;
        }
    }
// Todo: Confirm if looping is a threat
//    if ((ret = mbedtls_ssl_close_notify(&client->ssl)) < 0) {
//        print_err1("[Crypt]  mbedtls_ssl_close_notify returned %d\n", ret);
//        return false;
//    }
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

bool SecureSock::Client::connect(cs hostname, cs server_location, int port,
                                 cs ca_cert, bool require_client_auth) {
    int ret = 0;
    if ((ret = mbedtls_net_connect(&server_fd, server_location.c_str(), std::to_string(port).c_str(),
                                   MBEDTLS_NET_PROTO_TCP)) != 0) {
        print_err1("[Crypt]  mbedtls_net_connect returned %d\n", ret);
        close();
        return false;
    }
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        print_err1("[Crypt]  mbedtls_ssl_config_defaults returned %d\n", ret);
        close();
        return false;
    }
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, my_crypt->certificates[ca_cert], nullptr);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &my_crypt->ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, nullptr);
    mbedtls_debug_set_threshold(4);
    if (require_client_auth) {
        if ((ret = mbedtls_ssl_conf_own_cert(&conf, &my_crypt->my_cert, &my_crypt->my_private_key)) != 0) {
            print_err1("[Crypt]  mbedtls_ssl_conf_own_cert returned %d\n", ret);
            return false;
        }
    }
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        print_err1("[Crypt]  mbedtls_ssl_setup returned %d\n", ret);
        close();
        return false;
    }
    if ((ret = mbedtls_ssl_set_hostname(&ssl, hostname.c_str())) != 0) {
        print_err1("[Crypt]  mbedtls_ssl_set_hostname returned %d\n", ret);
        close();
        return false;
    }
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            print_err1("[Crypt]  mbedtls_ssl_handshake returned -0x%x\n", -ret);
            my_crypt->print_internal_error(ret);
            close();
            return false;
        }
    }
// Todo: Confirm if looping is a threat
//    if ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
//        print_err1("[Crypt]  mbedtls_ssl_handshake returned -0x%x\n", -ret);
//        my_crypt->print_internal_error(ret);
//        close();
//        return false;
//    }

    uint32_t flags;
    if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
        char vrfy_buf[512];
        print_err1("[Crypt]");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ", flags);
        print_err1("%s\n", vrfy_buf);
        return false;
    }
    return true;
}

ssize_t SecureSock::Client::read(s msg, size_t count) {
    int ret;
    unsigned char buf[count];
    memset(buf, 0, count);
    ret = mbedtls_ssl_read(&ssl, buf, count);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        return -1;
    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        return 0;
    if (ret < 0) {
        print_err1("[Crypt]  mbedtls_ssl_read returned %d\n", ret);
        return -1;
    }
    if (ret == 0) {
        print_err1("\n\nEOF\n");
        return 0;
    }
    msg.append(rcc(buf), static_cast<unsigned long>(ret));
    return ret;
}

ssize_t SecureSock::Client::write(cs msg) {
    int ret;
    while ((ret = mbedtls_ssl_write(&ssl, rccuc(msg.c_str()), msg.length())) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            print_err1("[Crypt]  peer closed the connection\n");
            return 0;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            print_err1("[Crypt]  mbedtls_ssl_write returned %d\n", ret);
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
