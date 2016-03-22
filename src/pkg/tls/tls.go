package tls

import (
    "time"
    "crypto/rand"
)

const (
    TLS_REC_TYPE_CHANGE_CIPHER_SPEC   uint8 = 0x14
    TLS_REC_TYPE_ALERT                uint8 = 0x15
    TLS_REC_TYPE_HANDSHAKE            uint8 = 0x16
    TLS_REC_TYPE_APPLICATION_DATA     uint8 = 0x17
    TLS_VERSION_SSL_3_0               uint16 = 0x0300
    TLS_VERSION_TLS_1_0               uint16 = 0x0301
    TLS_VERSION_TLS_1_1               uint16 = 0x0302
    TLS_VERSION_TLS_1_2               uint16 = 0x0303
    TLS_HANDSHAKE_HELLO_REQUEST       uint8 = 0x00
    TLS_HANDSHAKE_CLIENT_HELLO        uint8 = 0x01
    TLS_HANDSHAKE_SERVER_HELLO        uint8 = 0x02
    TLS_HANDSHAKE_CERTIFICATE         uint8 = 0x0b
    TLS_HANDSHAKE_SERVER_KEY_EXCHANGE uint8 = 0x0c
    TLS_HANDSHAKE_CERTIFICATE_REQUEST uint8 = 0x0d
    TLS_HANDSHAKE_SERVER_DONE         uint8 = 0x0e
    TLS_HANDSHAKE_CERTIFICATE_VERIFY  uint8 = 0x0f
    TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE uint8 = 0x10
    TLS_HANDSHAKE_FINISHED            uint8 = 0x14
    TLS_ALERT_WARNING                 uint8 = 0x01
    TLS_ALERT_FATAL                   uint8 = 0x02
    TLS_ALERT_CLOSE_NOTIFY            uint8 = 0x00
    TLS_ALERT_UNEXPECTED_MESSAGE      uint8 = 0x0a
    TLS_ALERT_BAD_RECORD_MAC          uint8 = 0x14
    TLS_ALERT_DESCRIPTION_FAILED      uint8 = 0x15
    TLS_ALERT_RECORD_OVERFLOW         uint8 = 0x16
    TLS_ALERT_DECOMPRESSION_FAILURE   uint8 = 0x1e
    TLS_ALERT_HANDSHAKE_FAILURE       uint8 = 0x28
    TLS_ALERT_NO_CERTIFICATE          uint8 = 0x29
    TLS_ALERT_BAD_CERTIFICATE         uint8 = 0x2a
    TLS_ALERT_UNSUPPORTED_CERTIFICATE uint8 = 0x2b
    TLS_ALERT_CERTIFICATE_REVOKED     uint8 = 0x2c
    TLS_ALERT_CERTIFICATE_EXPIRED     uint8 = 0x2d
    TLS_ALERT_CERTIFICATE_UNKNOWN     uint8 = 0x2e
    TLS_ALERT_ILLEGAL_PARAMETER       uint8 = 0x2f
    TLS_ALERT_UNKNOWN_CA              uint8 = 0x30
    TLS_ALERT_ACCESS_DENIED           uint8 = 0x31
    TLS_ALERT_DECODE_ERROR            uint8 = 0x32
    TLS_ALERT_DECRYPT_ERROR           uint8 = 0x33
    TLS_ALERT_EXPORT_RESTRICTION      uint8 = 0x3c
    TLS_ALERT_PROTOCOL_VERSION        uint8 = 0x46
    TLS_ALERT_INSUFFICIENT_SECURITY   uint8 = 0x47
    TLS_ALERT_INTERNAL_ERROR          uint8 = 0x50
    TLS_ALERT_USER_CANCELLED          uint8 = 0x5a
    TLS_ALERT_NO_RENEGOTIATION        uint8 = 0x64
//    TLS_CIPHER_SUITE_NULL_WITH_NULL_NULL uint16 = 0x0000
//    TLS_CIPHER_SUITE_RSA_WITH_NULL_MD5 uint16 = 0x0001
//    TLS_CIPHER_SUITE_RSA_WITH_NULL_SHA uint16 = 0x0002
//    TLS_CIPHER_SUITE_RSA_WITH_NULL_SHA256 uint16 = 0x003b
//    TLS_CIPHER_SUITE_RSA_WITH_RC4_128_MD5 uint16 = 0x0004
//    TLS_CIPHER_SUITE_RSA_WITH_RC4_128_SHA uint16 = 0x0005
//    TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA uint16 = 0x000a
    TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA uint16 = 0x002f
    TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA uint16 = 0x0035
    TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256 uint16 = 0x003c
    TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256 uint16 = 0x003d
)

func IsTLSClientHello(payload string) bool {
    return len(payload) >= 6 &&
           payload[0] == TLS_REC_TYPE_HANDSHAKE &&
           payload[5] == TLS_HANDSHAKE_CLIENT_HELLO
}

func GetCipherSuitesFromClientHello(payload string) []uint16 {
    if ! IsTLSClientHello(payload) || len(payload) <= 37 {
        return make([]uint16, 0)
    }
    offset := 43
    if payload[offset] > 0 {
        offset += int(payload[offset])
    }
    offset += 1
    var cipherSuitesLen uint16
    cipherSuitesLen = (uint16(payload[offset]) << 8) | uint16(payload[offset + 1])
    if cipherSuitesLen > 0 {
        cipherSuitesLen /= 2
    }
    ciphers := make([]uint16, 0)
    offset += 2
    var currCipher uint16
    for c := 0; c < int(cipherSuitesLen); c++ {
        currCipher = (uint16(payload[offset]) << 8) | uint16(payload[offset + 1])
        ciphers = append(ciphers, currCipher)
        offset += 2
    }
    return ciphers
}

func MkServerHello(tlsVersion int, cipherSuite uint16) []byte {
    helloBuf := make([]byte, 48)
    helloBuf[0] = TLS_REC_TYPE_HANDSHAKE
    var tlsTemp uint16 = TLS_VERSION_SSL_3_0
    switch tlsVersion {
        case 10:
            tlsTemp = TLS_VERSION_TLS_1_0
            break
        case 11:
            tlsTemp = TLS_VERSION_TLS_1_1
            break
        case 12:
            tlsTemp = TLS_VERSION_TLS_1_2
            break
        case 30:
            tlsTemp = TLS_VERSION_SSL_3_0
            break
    }
    helloBuf[1] = uint8(tlsTemp >> 8)
    helloBuf[2] = uint8(tlsTemp & 0xff)
    helloBuf[3] = 0x53
    helloBuf[4] = TLS_HANDSHAKE_SERVER_HELLO
    helloBuf[5] = 0x00
    helloBuf[6] = 0x00
    helloBuf[7] = 0x31
    helloBuf[8] = helloBuf[1]
    helloBuf[9] = helloBuf[2]
    // INFO(Santiago): Unix time & random
    var unixTime uint32 = uint32(time.Now().Unix())
    helloBuf[10] = uint8(unixTime >>  24)
    helloBuf[11] = uint8(unixTime >>  16)
    helloBuf[12] = uint8(unixTime >>   8)
    helloBuf[13] = uint8(unixTime & 0xff)
    rndBytes := make([]byte, 28)
    rand.Read(rndBytes)
    copy(helloBuf[14:], rndBytes)
    helloBuf[42] = 0x00
    helloBuf[43] = uint8(cipherSuite >> 8)
    helloBuf[44] = uint8(cipherSuite & 0xff)
    helloBuf[45] = 0x00
    //  INFO(Santiago): No extensions
    helloBuf[46] = 0x00
    helloBuf[47] = 0x00
    return helloBuf
}
