#include "aes-crypter.h"

#include <openssl/aes.h>
#include <openssl/evp.h>

AESCrypter::AESCrypter(unsigned char input_key[32], unsigned char input_iv[16]) {
    std::memcpy(key, input_key, sizeof(key));
    std::memcpy(iv, input_iv, sizeof(iv));
}

AESCrypterOutput AESCrypter::encrypt(const unsigned char *input, const int input_len) {
    EVP_CIPHER_CTX *ctx;

    AESCrypterOutput output;
    output.data = new unsigned char[input_len + AES_BLOCK_SIZE];
    memset(output.data, 0, input_len + AES_BLOCK_SIZE);
      
    int len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        throw std::runtime_error("AESCrypter: encrypt() - EVP_CIPHER_CTX_new() failed");

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        throw std::runtime_error("AESCrypter: encrypt() - EVP_EncryptInit_ex() failed");

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, output.data, &len, input, input_len))
        throw std::runtime_error("AESCrypter: encrypt() - EVP_EncryptUpdate() failed");
    output.data_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, output.data + len, &len))
        throw std::runtime_error("AESCrypter: encrypt() - EVP_EncryptFinal_ex() failed");

    output.data_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return output;
}

AESCrypterOutput AESCrypter::decrypt(const unsigned char *input, const int input_len) {
    EVP_CIPHER_CTX *ctx;

    AESCrypterOutput output;
    output.data = new unsigned char[input_len];
    memset(output.data, 0, input_len);

    int len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        throw std::runtime_error("AESCrypter: decrypt() - EVP_CIPHER_CTX_new() failed");

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        throw std::runtime_error("AESCrypter: decrypt() - EVP_DecryptInit_ex() failed");

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, output.data, &len, input, input_len))
        throw std::runtime_error("AESCrypter: decrypt() - EVP_DecryptUpdate() failed");

    output.data_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, output.data + len, &len))
        throw std::runtime_error("AESCrypter: decrypt() - EVP_DecryptFinal_ex() failed");
    
    output.data_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return output;
}
