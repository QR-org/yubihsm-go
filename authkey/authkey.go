package authkey

import (
	"crypto/pbkdf2"
	"crypto/sha256"
)

type (
	// AuthKey is a key to authenticate with the HSM
	AuthKey []byte
)

const (
	authKeyLength     = 32
	authKeyIterations = 10000
	yubicoSeed        = "Yubico"
)

// FromPassword derives an AuthKey using pbkdf2 as specified in the HSM documentation.
// It fails in FIPS 140-only mode, which does not allow the 6-byte salt the HSM uses.
func FromPassword(password string) (AuthKey, error) {
	return pbkdf2.Key(sha256.New, password, []byte(yubicoSeed), authKeyIterations, authKeyLength)
}

// NewFromPassword derives an AuthKey like FromPassword and panics if FromPassword fails.
func NewFromPassword(password string) AuthKey {
	k, err := FromPassword(password)
	if err != nil {
		panic(err)
	}
	return k
}

// GetEncKey returns the EncryptionKey part of the AuthKey
func (k AuthKey) GetEncKey() []byte {
	return k[:authKeyLength/2]
}

// GetMacKey returns the MACKey part of the AuthKey
func (k AuthKey) GetMacKey() []byte {
	return k[authKeyLength/2:]
}
