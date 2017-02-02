// +build gofuzz

package lioness

import (
	"bytes"
	"encoding/hex"
)

// Fuzz uses go-fuzz https://github.com/dvyukov/go-fuzz
func Fuzz(data []byte) int {
	if len(data) <= 32 {
		return -1
	}
	keyStr := "0f2c69732932c99e56fa50fbb2763ad77ee221fc5d9e6c08f89fc577a7467f1ee34" +
		"003440ee2bfbfaac60912b0e547fbe9a6a9292db70bc718c6f2773ab198ac8f25537" +
		"8f7ea799e1d4b8596079173b6e443c416f13195f1976acc03d53a4b8581b609df3b7" +
		"029d5b487051d5ae4189129c045edc8822e1f52e30251e4b322b3f6d6e8bb0ddb057" +
		"8dcba41603abf5e51848c84d2082d293f30a645faf4df028ee2c40853ea33e40b55f" +
		"ca902371dc00dc1e0e77161bd097a59e8368bf99174d9"
	key, err := hex.DecodeString(keyStr)
	var cipherKey [KeyLen]byte
	copy(cipherKey[:], key)
	cipher, err := NewCipher(cipherKey, len(data))
	if err != nil {
		return 1
	}
	ciphertext, err := cipher.Encrypt(data)
	if err != nil {
		return 1
	}
	plaintext, err := cipher.Decrypt(ciphertext)
	if err != nil {
		return 1
	}
	if !bytes.Equal(plaintext, data) {
		return 1
	}
	return 0
}
