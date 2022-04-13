import { NativeModules } from 'react-native';

// /src/index.tsx
const PharioEncryptionModule = NativeModules.PharioEncryption;

if (PharioEncryptionModule) {
  if (typeof PharioEncryptionModule.install === 'function') {
    PharioEncryptionModule.install();
  }
}

interface PharioEncryption {
  encryptAES(
    input: ArrayBuffer,
    key: ArrayBuffer,
    iv: ArrayBuffer
  ): ArrayBuffer;

  decryptAES(
    input: ArrayBuffer,
    key: ArrayBuffer,
    iv: ArrayBuffer
  ): ArrayBuffer;

  secureGenRandomBytes(keySize: number): ArrayBuffer;

  hkdf(
    key: ArrayBuffer,
    salt: ArrayBuffer,
    info: ArrayBuffer,
    keySize: number
  ): ArrayBuffer;

  pbkdf2(
    password: ArrayBuffer,
    salt: ArrayBuffer,
    outputSize: number,
    iterations: number
  ): ArrayBuffer;
}

// global declaration
declare global {
  function pharioEncryptionCreateNewInstance(): PharioEncryption;
}

export default global.pharioEncryptionCreateNewInstance();
