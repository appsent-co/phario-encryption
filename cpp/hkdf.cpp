//
//  hkdf.cpp
//  phario-encryption
//
//  Created by Maxence Henneron on 4/8/22.
//

#include "hkdf.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>

void HKDF(
              uint8_t *key, int key_len,
              uint8_t *salt, int salt_len,
              uint8_t *info, int info_len,
              uint8_t *out, size_t output_byte_count
              ) {
    EVP_PKEY_CTX *pctx;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0)
        throw std::runtime_error("HKDF - EVP_PKEY_derive_init() failed");
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0)
        throw std::runtime_error("HKDF - EVP_PKEY_CTX_set_hkdf_md() failed");
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0)
        throw std::runtime_error("HKDF - EVP_PKEY_CTX_set1_hkdf_salt() failed");
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key, key_len) <= 0)
        throw std::runtime_error("HKDF - EVP_PKEY_CTX_set1_hkdf_key() failed");
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0)
        throw std::runtime_error("HKDF - EVP_PKEY_CTX_add1_hkdf_info() failed");
    if (EVP_PKEY_derive(pctx, out, &output_byte_count) <= 0)
        throw std::runtime_error("HKDF - EVP_PKEY_derive() failed");
        
    EVP_PKEY_CTX_free(pctx);
}
