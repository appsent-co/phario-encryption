//
//  pbkdf2.hpp
//  phario-encryption
//
//  Created by Maxence Henneron on 4/8/22.
//

#ifndef pbkdf2_hpp
#define pbkdf2_hpp

#include <string>

void PBKDF2_HMAC_SHA_256(const uint8_t* pass, int passlen, const uint8_t* salt, int saltlen, size_t iterations, size_t outputBytes, uint8_t* binResult);

#endif /* pbkdf2_hpp */
