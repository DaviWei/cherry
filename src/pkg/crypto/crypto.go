package crypto

import (
    "crypto/rsa"
    "crypto/rand"
    "crypto/aes"
    "crypto/cipher"
    "io"
)

func RSADecryptSessionKey(ciphertext []byte, privateKey *rsa.PrivateKey) []byte {
    rng := rand.Reader
    key := make([]byte, 32)
    if _, err := io.ReadFull(rng, key); err != nil {
        return make([]byte, 0)
    }
    if err := rsa.DecryptPKCS1v15SessionKey(rng, privateKey, ciphertext, key); err != nil {
        return make([]byte, 0)
    }
    return key
}

func AESCBCEncrypt(plaintext, key []byte) []byte {
    aesKeys, err := aes.NewCipher(key)
    if err != nil {
        return make([]byte, 0)
    }
    ciphertext := make([]byte, aes.BlockSize + len(plaintext))
    iv := make([]byte, aes.BlockSize)
    rand.Read(iv)
    copy(ciphertext, iv)
    cbcEncrypter := cipher.NewCBCEncrypter(aesKeys, iv)
    cbcEncrypter.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
    return ciphertext
}

func AESCBCDecrypt(ciphertext, key []byte) []byte {
    aesKeys, err := aes.NewCipher(key)
    if err != nil {
        return make([]byte, 0)
    }
    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]
    if len(ciphertext) % aes.BlockSize != 0 {
        return make([]byte, 0)
    }
    cbcDecrypter := cipher.NewCBCDecrypter(aesKeys, iv)
    cbcDecrypter.CryptBlocks(ciphertext, ciphertext)
    return ciphertext
}
