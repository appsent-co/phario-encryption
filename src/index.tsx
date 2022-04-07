import { NativeModules } from 'react-native';

// /src/index.tsx
const PharioEncryptionModule = NativeModules.PharioEncryption;

if (PharioEncryptionModule) {
  if (typeof PharioEncryptionModule.install === 'function') {
    PharioEncryptionModule.install();
  }
}

// global declaration
declare global {
  function encryptAES(
    input: ArrayBuffer,
    key: ArrayBuffer,
    iv: ArrayBuffer
  ): ArrayBuffer;

  function decryptAES(
    input: ArrayBuffer,
    key: ArrayBuffer,
    iv: ArrayBuffer
  ): ArrayBuffer;

  function secureGenRandomBytes(keySize: number): ArrayBuffer;
}

export const encryptAES = global.encryptAES;
export const decryptAES = global.decryptAES;
export const secureGenRandomBytes = global.secureGenRandomBytes;
