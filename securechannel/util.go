package securechannel

import (
	"bytes"
	"crypto/aes"
	"errors"
)

var errInvalidPadding = errors.New("invalid SCP03 padding")

// pad adds a padding to src until using the mechanism specified in SCP03 until it has a len that is a multiple of
// aes.BlockSize and returns the result
func pad(src []byte) []byte {
	if aes.BlockSize-len(src)%aes.BlockSize == 0 {
		return src
	}

	padding := aes.BlockSize - len(src)%aes.BlockSize - 1
	padtext := bytes.Repeat([]byte{0}, padding)
	padtext = append([]byte{0x80}, padtext...)
	return append(src, padtext...)
}

// unpad removes the padding from src using the mechanism specified in SCP03 and returns the result.
// The padding is a 0x80 byte followed by zero or more 0x00 bytes, at most one block in total.
func unpad(src []byte) ([]byte, error) {
	for i := len(src) - 1; i >= 0 && len(src)-i <= aes.BlockSize; i-- {
		switch src[i] {
		case 0x00:
		case 0x80:
			return src[:i], nil
		default:
			return nil, errInvalidPadding
		}
	}
	return nil, errInvalidPadding
}
