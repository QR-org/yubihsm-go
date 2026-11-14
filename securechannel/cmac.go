package securechannel

import (
	"crypto/aes"
	"crypto/subtle"
)

// cmacAES returns the AES-CMAC of msg under key, as specified in RFC 4493.
func cmacAES(key, msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	k1 := make([]byte, aes.BlockSize)
	block.Encrypt(k1, k1)
	k1 = cmacDouble(k1)
	k2 := cmacDouble(k1)

	n := (len(msg) + aes.BlockSize - 1) / aes.BlockSize
	last := make([]byte, aes.BlockSize)
	if n > 0 && len(msg)%aes.BlockSize == 0 {
		subtle.XORBytes(last, msg[(n-1)*aes.BlockSize:], k1)
	} else {
		n = max(n, 1)
		tail := msg[(n-1)*aes.BlockSize:]
		copy(last, tail)
		last[len(tail)] = 0x80
		subtle.XORBytes(last, last, k2)
	}

	x := make([]byte, aes.BlockSize)
	for i := 0; i < n-1; i++ {
		subtle.XORBytes(x, x, msg[i*aes.BlockSize:(i+1)*aes.BlockSize])
		block.Encrypt(x, x)
	}
	subtle.XORBytes(x, x, last)
	block.Encrypt(x, x)
	return x, nil
}

// cmacDouble multiplies b by x in GF(2^128), the subkey step of RFC 4493.
func cmacDouble(b []byte) []byte {
	out := make([]byte, len(b))
	for i := 0; i < len(b)-1; i++ {
		out[i] = b[i]<<1 | b[i+1]>>7
	}
	out[len(b)-1] = b[len(b)-1]<<1 ^ 0x87&-(b[0]>>7)
	return out
}
