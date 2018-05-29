#include "Crypt.h"
#include <cstdlib>
#include <cstdio>

using std::string;

int main(int argc, char **argv) {
    Crypt crypt;
    // TODO: get rid of env vars from CLion files
    crypt.initialize(getenv("PER_STRING"));
    crypt.load_private_key(getenv("SRINSKIT_CA_KEY"), getenv("SRINSKIT_CA_PASS"));
    crypt.add_cert("self", getenv("SRINSKIT_CA_CERT"));
    string hmm, result;
    crypt.encrypt("Hello World!", "self", hmm);
    crypt.decrypt(hmm, result);
    printf("%s\n", result.c_str());
    hmm.clear();
    result.clear();
    crypt.sign("World Hello!", hmm);
    if (crypt.verify("World Hello!", hmm, "self")) {
        printf("Woah!\n");
    }
    crypt.terminate();
    return 0;
}