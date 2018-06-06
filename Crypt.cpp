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
        perror("CRYPT-INIT-1");
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
        printf("[FAIL] mbedtls_pk_parse_keyfile returned -0x%04x\n", -ret);
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
        printf("[FAIL] mbedtls_pk_encrypt returned -0x%04x\n", -ret);
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
        printf("[FAIL] mbedtls_pk_decrypt returned -0x%04x\n", -ret);
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
        printf("[FAIL] mbedtls_pk_sign returned -0x%04x\n", -ret);
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
        printf("[FAIL] mbedtls_pk_verify returned -0x%04x\n", -ret);
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
