package crtio

import (
    "encoding/pem"
    "os"
    "bufio"
    "crypto/x509"
    "crypto/rsa"
)

func GetBytesFromPEM(pempath string) []byte {
    pemFile, err := os.Open(pempath)
    if err != nil {
        return make([]byte, 0)
    }
    pemFileInfo, statErr := pemFile.Stat()
    if statErr != nil {
        pemFile.Close()
        return make([]byte, 0)
    }
    pemFileSize := pemFileInfo.Size()
    pemCode := make([]byte, pemFileSize)
    buffer := bufio.NewReader(pemFile)
    _, err = buffer.Read(pemCode)
    pemFile.Close()
    pemData, _ := pem.Decode(pemCode)
    return pemData.Bytes
}

func GetRSAPrivateKeyFromBuffer(buffer []byte) (key *rsa.PrivateKey, err error) {
    return x509.ParsePKCS1PrivateKey(buffer)
}
