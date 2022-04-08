//
//  pbkdf2.cpp
//  phario-encryption
//
//  Created by Maxence Henneron on 4/8/22.
//

#include "pbkdf2.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <string>

void PBKDF2_HMAC_SHA_256(const uint8_t* pass, int passlen, const uint8_t* salt, int saltlen, size_t iterations, size_t outputBytes, uint8_t* binResult)
{
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC((const char*) pass, passlen, salt, saltlen, iterations, EVP_sha256(), outputBytes, digest);
    memcpy(binResult, digest, sizeof(digest));
}
