import { NativeModules } from 'react-native';

// /src/index.tsx
const PharioEncryptionModule = NativeModules.PharioEncryption;

if (PharioEncryptionModule) {
  if (typeof PharioEncryptionModule.install === 'function') {
    PharioEncryptionModule.install();
  }
}

declare function multiply(a: number, b: number): number;

export function multiplyA(): number {
  return multiply(2, 2);
}
