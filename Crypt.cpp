/*
    Made with ❤ by srinSkit.
    Created on 28 May 2018.
*/

#include "Crypt.h"

/*
 * Initialize libraries
 * return true on success, false on failure
 */
bool Crypt::initialize(const std::string &personalize) {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    auto ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     reinterpret_cast<const unsigned char *>(personalize.c_str()),
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
    for (auto &certificate : certificates)
        delete (certificate.second);
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
                                  reinterpret_cast<const unsigned char *>(msg.c_str()), msg.length(), result, &olen,
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
    auto ret = mbedtls_pk_decrypt(&my_private_key, reinterpret_cast<const unsigned char *>(dump.c_str()), dump.length(),
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
    mbedtls_sha256(reinterpret_cast<const unsigned char *>(msg.c_str()), msg.length(), hash, 0);
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
    mbedtls_sha256(reinterpret_cast<const unsigned char *>(msg.c_str()), msg.length(), hash, 0);
    // TODO: check why verify seems to work with my_private_key too
    auto ret = mbedtls_pk_verify(&certificates[name]->pk, MBEDTLS_MD_NONE, hash, sizeof(hash),
                                 reinterpret_cast<const unsigned char *>(dump.c_str()), dump.length());
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
    return std::string(reinterpret_cast<char *>(certificates[name]->raw.p), certificates[name]->raw.len);
}


bool Crypt::certify_string(const std::string &buff, const std::string &common_name) {
    if (certificates.find(common_name) != certificates.end())
        return false;
    auto certificate = new mbedtls_x509_crt;
    mbedtls_x509_crt_init(certificate);
    if (mbedtls_x509_crt_parse(certificate, reinterpret_cast<const unsigned char *>(buff.c_str()), buff.length()) ==
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

SecureSock::SecureSock(Crypt *crypt) {
    my_crypt = crypt;
}

bool SecureSock::init(bool is_client, int port) {
    this->is_client = is_client;
    this->port = std::to_string(port);
    if (!is_client) {
        mbedtls_net_init(&listen_fd);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
    } else {

    }
    return true;
}


bool SecureSock::start() {
    int ret;
    if (!is_client) {
        if ((ret = mbedtls_net_bind(&listen_fd, nullptr, port.c_str(), MBEDTLS_NET_PROTO_TCP)) != 0) {
            mbedtls_printf(" [FAIL]\n  ! mbedtls_net_bind returned %d\n\n", ret);
            return false;
        }
        if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                               MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
            return false;
        }
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &my_crypt->ctr_drbg);
        mbedtls_ssl_conf_dbg(&conf, nullptr, stdout);
        mbedtls_ssl_conf_ca_chain(&conf, my_crypt->my_cert.next, nullptr);
        if ((ret = mbedtls_ssl_conf_own_cert(&conf, &my_crypt->my_cert, &my_crypt->my_private_key)) != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
            return false;
        }
        if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
            return false;
        }
        mbedtls_net_context client_fd;
        mbedtls_net_init(&client_fd);
        reset:
        mbedtls_net_free(&client_fd);
        mbedtls_ssl_session_reset(&ssl);
        if ((ret = mbedtls_net_accept(&listen_fd, &client_fd, nullptr, 0, nullptr)) != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
            return false;
        }
        mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);
        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret);
                goto reset;
            }
        }


//        do {
//            len = sizeof(buf) - 1;
//            memset(buf, 0, sizeof(buf));
//            ret = mbedtls_ssl_read(&ssl, buf, len);
//
//            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
//                continue;
//            if (ret <= 0) {
//                switch (ret) {
//                    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
//                        mbedtls_printf(" connection was closed gracefully\n");
//                        break;
//
//                    case MBEDTLS_ERR_NET_CONN_RESET:
//                        mbedtls_printf(" connection was reset by peer\n");
//                        break;
//
//                    default:
//                        mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", -ret);
//                        break;
//                }
//
//                break;
//            }
//
//            len = ret;
//            mbedtls_printf(" %d bytes read\n\n%s", len, (char *) buf);
//
//            if (ret > 0)
//                break;
//        } while (1);

    } else {

    }
    return true;
}
