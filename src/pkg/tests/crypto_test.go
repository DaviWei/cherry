package cherry_test

import (
    "testing"
    "pkg/crypto"
)

func TestAesEncryption(t *testing.T) {
    key128 := []byte("0000000000000000")
    key192 := []byte("000000000000000000000000")
    key256 := []byte("00000000000000000000000000000000")
    plaintext := []byte("subi num onibus em marrocos-----")
    ciphertext := crypto.AESCBCEncrypt(plaintext, key128)
    temp := crypto.AESCBCDecrypt(ciphertext, key128)
    if len(temp) != len(plaintext) {
        t.Fail()
    }
    for p := 0; p < len(temp); p++ {
        if temp[p] != plaintext[p] {
            t.Fail()
        }
    }

    ciphertext = crypto.AESCBCEncrypt(plaintext, key192)
    temp = crypto.AESCBCDecrypt(ciphertext, key192)
    if len(temp) != len(plaintext) {
        t.Fail()
    }
    for p := 0; p < len(temp); p++ {
        if temp[p] != plaintext[p] {
            t.Fail()
        }
    }

    ciphertext = crypto.AESCBCEncrypt(plaintext, key256)
    temp = crypto.AESCBCDecrypt(ciphertext, key256)
    if len(temp) != len(plaintext) {
        t.Fail()
    }
    for p := 0; p < len(temp); p++ {
        if temp[p] != plaintext[p] {
            t.Fail()
        }
    }
}
