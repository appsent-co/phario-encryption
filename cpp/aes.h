#ifndef PHARIO_AES_H
#define PHARIO_AES_H

#include <string>

typedef struct {
    uint8_t *data;
    size_t data_len;
} AESCrypterOutput;

class AESCrypter {
private:
    uint8_t key[32];
    uint8_t iv[16];

public:
    AESCrypter(uint8_t input_key[32], uint8_t input_iv[16]);

    AESCrypterOutput encrypt(const uint8_t *input, const int input_len);
    AESCrypterOutput decrypt(const uint8_t *input, const int input_len);
};

#endif //DFS_SSL_CRYPTER_H
