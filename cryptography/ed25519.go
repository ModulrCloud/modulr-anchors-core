package cryptography

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"

	"github.com/btcsuite/btcutil/base58"
)

func GenerateSignature(base64PrivateKey, msg string) string {
	// Decode private key from base64 to raw bytes
	privateKeyAsBytes, _ := base64.StdEncoding.DecodeString(base64PrivateKey)

	// Deserialize private key
	privKeyInterface, _ := x509.ParsePKCS8PrivateKey(privateKeyAsBytes)
	finalPrivateKey := privKeyInterface.(ed25519.PrivateKey)

	msgAsBytes := []byte(msg)
	signature, _ := finalPrivateKey.Sign(rand.Reader, msgAsBytes, crypto.Hash(0))

	return base64.StdEncoding.EncodeToString(signature)
}

func VerifySignature(message, base58PubKey, base64Signature string) bool {
	// Decode everything
	msgAsBytes := []byte(message)
	publicKeyAsBytesWithNoAsnPrefix := base58.Decode(base58PubKey)

	// Add ASN.1 prefix
	pubKeyAsBytesWithAsnPrefix := append([]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}, publicKeyAsBytesWithNoAsnPrefix...)
	pubKeyInterface, _ := x509.ParsePKIXPublicKey(pubKeyAsBytesWithAsnPrefix)
	finalPubKey := pubKeyInterface.(ed25519.PublicKey)

	signature, _ := base64.StdEncoding.DecodeString(base64Signature)

	return ed25519.Verify(finalPubKey, msgAsBytes, signature)
}
