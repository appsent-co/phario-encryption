#ifndef DFS_SSL_CRYPTER_H
#define DFS_SSL_CRYPTER_H

#include <string>

typedef struct {
    uint8_t *data;
    size_t data_len;
} AESCrypterOutput;

class AESCrypter {
private:
    unsigned char key[32];
    unsigned char iv[16];

public:
    AESCrypter(unsigned char input_key[32], unsigned char input_iv[16]);

    AESCrypterOutput encrypt(const unsigned char *input, const int input_len);
    AESCrypterOutput decrypt(const unsigned char *input, const int input_len);
};

#endif //DFS_SSL_CRYPTER_H
