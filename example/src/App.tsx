import * as React from 'react';

import { StyleSheet, View, Text } from 'react-native';
import PharioEncryption from '@appsent-co/phario-encryption';

export default function App() {
  const [aesResult, setAesResult] = React.useState<string | undefined>();

  function str2ab(str: string) {
    var buf = new ArrayBuffer(str.length); // 2 bytes for each char
    var bufView = new Uint8Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }

  function ab2str(buf: ArrayBuffer) {
    var binaryString = '',
      bytes = new Uint8Array(buf),
      length = bytes.length;
    for (var i = 0; i < length; i++) {
      binaryString += String.fromCharCode(bytes[i]);
    }
    return binaryString;
  }

  React.useEffect(() => {
    const key = PharioEncryption.secureGenRandomBytes(32);
    const iv = PharioEncryption.secureGenRandomBytes(16);

    const data = str2ab('Hello, world!');
    const encryptedData = PharioEncryption.encryptAES(data, key, iv);
    const decryptedData = PharioEncryption.decryptAES(encryptedData, key, iv);

    const salt = new Uint8Array(
      '30259b72ccbc6d3dbcdb76d206f10006'
        .match(/../g)
        ?.map((h) => parseInt(h, 16)) ?? [0]
    ).buffer;

    const email = str2ab('nobody@nowhere.com');
    const password = str2ab('guess-magpie-homeland-quanta');
    const info = str2ab('PBES2g-HS256');

    const hkdfResult = PharioEncryption.hkdf(salt, email, info, 32);
    const pbkResult = PharioEncryption.pbkdf2(password, hkdfResult, 32, 100000);
    console.log(pbkResult.byteLength);
    // new TextEncoder().encode('Test string');

    setAesResult(ab2str(decryptedData));
  }, []);

  return (
    <View style={styles.container}>
      <Text>Aes encryption/decryption result: {aesResult}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 60,
    height: 60,
    marginVertical: 20,
  },
});
