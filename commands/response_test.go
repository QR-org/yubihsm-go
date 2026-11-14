package commands

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func frame(cmd CommandType, payload []byte) []byte {
	data := []byte{byte(cmd) + ResponseCommandOffset, 0, 0}
	binary.BigEndian.PutUint16(data[1:3], uint16(len(payload)))
	return append(data, payload...)
}

func TestParseGenerateAsymmetricKeyResponse(t *testing.T) {
	resp, err := ParseResponse(frame(CommandTypeGenerateAsymmetricKey, []byte{0x12, 0x34}))
	if err != nil {
		t.Fatal(err)
	}
	r, ok := resp.(*CreateAsymmetricKeyResponse)
	if !ok {
		t.Fatalf("response is %T", resp)
	}
	if r.KeyID != 0x1234 {
		t.Errorf("KeyID = 0x%04x, want 0x1234", r.KeyID)
	}
}

func TestParseSessionMessage(t *testing.T) {
	payload := append([]byte{7}, bytes.Repeat([]byte{0xee}, 16)...)
	payload = append(payload, bytes.Repeat([]byte{0xaa}, 8)...)
	resp, err := ParseResponse(frame(CommandTypeSessionMessage, payload))
	if err != nil {
		t.Fatal(err)
	}
	r := resp.(*SessionMessageResponse)
	if r.SessionID != 7 || len(r.EncryptedData) != 16 || !bytes.Equal(r.MAC, bytes.Repeat([]byte{0xaa}, 8)) {
		t.Errorf("got %+v", r)
	}
}

func TestParseDeviceInfoResponse(t *testing.T) {
	payload := []byte{2, 2, 0, 0x00, 0x12, 0x34, 0x56, 62, 5, byte(AlgorithmSecp256k1)}
	resp, err := ParseResponse(frame(CommandTypeDeviceInfo, payload))
	if err != nil {
		t.Fatal(err)
	}
	r := resp.(*DeviceInfoResponse)
	if r.MajorVersion != 2 || r.SerialNumber != 0x123456 || r.LogTotal != 62 || r.LogUsed != 5 ||
		len(r.SupportedAlgorithms) != 1 || r.SupportedAlgorithms[0] != AlgorithmSecp256k1 {
		t.Errorf("got %+v", r)
	}
}

func TestParseResponseRejectsMalformedPayloads(t *testing.T) {
	tests := []struct {
		name    string
		cmd     CommandType
		payload []byte
	}{
		{"generate key, short", CommandTypeGenerateAsymmetricKey, []byte{0x12}},
		{"generate key, long", CommandTypeGenerateAsymmetricKey, []byte{0x12, 0x34, 0x80}},
		{"session message, empty", CommandTypeSessionMessage, nil},
		{"session message, no room for MAC", CommandTypeSessionMessage, make([]byte, 8)},
		{"device info, empty", CommandTypeDeviceInfo, nil},
		{"device info, short", CommandTypeDeviceInfo, make([]byte, 8)},
		{"sign ecdsa, empty", CommandTypeSignDataEcdsa, nil},
		{"sign eddsa, empty", CommandTypeSignDataEddsa, nil},
		{"create session, short", CommandTypeCreateSession, make([]byte, 16)},
		{"list objects, partial entry", CommandTypeListObjects, make([]byte, 5)},
		{"object info, short", CommandTypeGetObjectInfo, make([]byte, 10)},
		{"get public key, empty", CommandTypeGetPubKey, nil},
		{"import wrapped, short", CommandTypeImportWrapped, make([]byte, 2)},
		{"export wrapped, short", CommandTypeExportWrapped, make([]byte, 12)},
		{"error, empty", ErrorResponseCode - ResponseCommandOffset, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ParseResponse(frame(tt.cmd, tt.payload))
			if err == nil {
				t.Fatalf("got %+v, want an error", resp)
			}
		})
	}
}

func TestParseResponseRejectsMalformedFrames(t *testing.T) {
	tests := map[string][]byte{
		"empty":            nil,
		"header only":      {0x86, 0x00},
		"length too long":  {0x86, 0x00, 0x05, 0x01},
		"length too short": {0x86, 0x00, 0x00, 0x01},
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseResponse(data); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func FuzzParseResponse(f *testing.F) {
	f.Add(frame(CommandTypeGenerateAsymmetricKey, []byte{0x12, 0x34}))
	f.Add(frame(CommandTypeSessionMessage, make([]byte, 25)))
	f.Add(frame(CommandTypeDeviceInfo, make([]byte, 12)))
	f.Add(frame(CommandTypeGetObjectInfo, make([]byte, 66)))
	f.Add(frame(CommandTypeListObjects, make([]byte, 8)))
	f.Add([]byte{0xff, 0x00, 0x01, 0x0b})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseResponse(data)
	})
}
