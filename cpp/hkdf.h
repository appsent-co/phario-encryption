//
//  hkdf.hpp
//  phario-encryption
//
//  Created by Maxence Henneron on 4/8/22.
//

#ifndef hkdf_hpp
#define hkdf_hpp

#include <string>

void HKDF(
              uint8_t *key, int key_len,
              uint8_t *salt, int salt_len,
              uint8_t *info, int info_len,
              uint8_t *out, size_t output_byte_count
              );

#endif /* hkdf_hpp */
