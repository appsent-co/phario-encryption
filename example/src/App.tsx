import * as React from 'react';

import { StyleSheet, View, Text } from 'react-native';
import {
  encryptAES,
  decryptAES,
  secureGenRandomBytes,
} from '@appsent-co/phario-encryption';

export default function App() {
  const [result, setResult] = React.useState<string | undefined>();

  function str2ab(str: string) {
    var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
    var bufView = new Uint16Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }

  function ab2str(buf: ArrayBuffer) {
    var binaryString = '',
      bytes = new Uint16Array(buf),
      length = bytes.length;
    for (var i = 0; i < length; i++) {
      binaryString += String.fromCharCode(bytes[i]);
    }
    return binaryString;
  }

  React.useEffect(() => {
    const key = secureGenRandomBytes(32);
    const iv = secureGenRandomBytes(16);
    const data = str2ab('Hello, world! 🌈');
    const encryptedData = encryptAES(data, key, iv);
    const decryptedData = decryptAES(encryptedData, key, iv);

    setResult(ab2str(decryptedData));
  }, []);

  return (
    <View style={styles.container}>
      <Text>Result: {result}</Text>
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
