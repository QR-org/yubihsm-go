package securechannel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
)

func TestUnpad(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    []byte
		wantErr bool
	}{
		{"marker only", []byte{1, 2, 0x80}, []byte{1, 2}, false},
		{"marker and zeros", []byte{1, 0x00, 0x80, 0, 0}, []byte{1, 0x00}, false},
		{"full block", append([]byte{0x80}, make([]byte, 15)...), []byte{}, false},
		{"empty", nil, nil, true},
		{"no marker", []byte{1, 2, 3}, nil, true},
		{"zeros only", make([]byte, 16), nil, true},
		{"padding longer than a block", append([]byte{1, 0x80}, make([]byte, 16)...), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unpad(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !bytes.Equal(got, tt.want) {
				t.Errorf("got %x, want %x", got, tt.want)
			}
		})
	}
}

func TestPadUnpadRoundTrip(t *testing.T) {
	for n := 0; n <= 2*aes.BlockSize; n++ {
		in := bytes.Repeat([]byte{0x80}, n)
		padded := pad(bytes.Clone(in))
		if len(padded)%aes.BlockSize != 0 {
			t.Fatalf("len(pad(%d bytes)) = %d", n, len(padded))
		}
		got, err := unpad(padded)
		if err != nil || !bytes.Equal(got, in) {
			t.Fatalf("unpad(pad(%d bytes)) = %x, %v", n, got, err)
		}
	}
}

func FuzzUnpad(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 0x80, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := unpad(data)
		if err == nil && (len(got) >= len(data) || data[len(got)] != 0x80) {
			t.Fatalf("unpad(%x) = %x", data, got)
		}
	})
}

// fakeConnector answers every request with respond(s), where s is the channel
// in the state it has after MACing the command.
type fakeConnector struct {
	s       *SecureChannel
	respond func(s *SecureChannel) []byte
}

func (c *fakeConnector) Request(*commands.CommandMessage) ([]byte, error) {
	return c.respond(c.s), nil
}

func (c *fakeConnector) GetStatus() (*connector.StatusResponse, error) { return nil, nil }

func newTestChannel(t *testing.T, respond func(s *SecureChannel) []byte) *SecureChannel {
	t.Helper()
	s := &SecureChannel{
		ID:            3,
		Counter:       1,
		SecurityLevel: SecurityLevelAuthenticated,
		MACChainValue: make([]byte, 16),
		keyChain: &KeyChain{
			EncKey:  bytes.Repeat([]byte{0x01}, KeyLength),
			MACKey:  bytes.Repeat([]byte{0x02}, KeyLength),
			RMACKey: bytes.Repeat([]byte{0x03}, KeyLength),
		},
	}
	s.connector = &fakeConnector{s: s, respond: respond}
	return s
}

// encrypt encrypts plain like the device does for the current counter.
func encrypt(t *testing.T, s *SecureChannel, plain []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(s.keyChain.EncKey)
	if err != nil {
		t.Fatal(err)
	}
	icv := make([]byte, aes.BlockSize)
	binary.BigEndian.PutUint32(icv[12:], s.Counter)
	iv := make([]byte, aes.BlockSize)
	block.Encrypt(iv, icv)
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return out
}

// sessionResponse frames encrypted as a session message with a valid MAC.
func sessionResponse(t *testing.T, s *SecureChannel, encrypted []byte) []byte {
	t.Helper()
	msg := &commands.CommandMessage{
		CommandType: commands.CommandTypeSessionMessage + commands.ResponseCommandOffset,
		SessionID:   &s.ID,
		Data:        encrypted,
	}
	mac, err := s.calculateMAC(msg, MessageTypeResponse)
	if err != nil {
		t.Fatal(err)
	}
	msg.MAC = mac[:MACLength]
	data, _ := msg.Serialize()
	return data
}

func echoCommand(t *testing.T) *commands.CommandMessage {
	t.Helper()
	cmd, err := commands.CreateEchoCommand([]byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}

func TestSendEncryptedCommand(t *testing.T) {
	s := newTestChannel(t, nil)
	s.connector.(*fakeConnector).respond = func(s *SecureChannel) []byte {
		inner := []byte{byte(commands.CommandTypeEcho) + commands.ResponseCommandOffset, 0, 2, 'h', 'i'}
		return sessionResponse(t, s, encrypt(t, s, pad(inner)))
	}
	resp, err := s.SendEncryptedCommand(echoCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := resp.(*commands.EchoResponse); !ok || string(r.Data) != "hi" {
		t.Fatalf("got %#v", resp)
	}
	if s.Counter != 2 {
		t.Errorf("Counter = %d, want 2", s.Counter)
	}
}

func TestSendEncryptedCommandRejectsMalformedResponses(t *testing.T) {
	tests := []struct {
		name        string
		respond     func(t *testing.T, s *SecureChannel) []byte
		wantCounter uint32
	}{
		{"short session message", func(t *testing.T, s *SecureChannel) []byte {
			return []byte{byte(commands.CommandTypeSessionMessage) + commands.ResponseCommandOffset, 0, 3, s.ID, 0, 0}
		}, 1},
		{"wrong MAC", func(t *testing.T, s *SecureChannel) []byte {
			data := sessionResponse(t, s, make([]byte, aes.BlockSize))
			data[len(data)-1] ^= 1
			return data
		}, 1},
		{"encrypted data not a block multiple", func(t *testing.T, s *SecureChannel) []byte {
			return sessionResponse(t, s, make([]byte, aes.BlockSize+1))
		}, 2},
		{"no encrypted data", func(t *testing.T, s *SecureChannel) []byte {
			return sessionResponse(t, s, nil)
		}, 2},
		{"no padding marker", func(t *testing.T, s *SecureChannel) []byte {
			return sessionResponse(t, s, encrypt(t, s, bytes.Repeat([]byte{0x01}, aes.BlockSize)))
		}, 2},
		{"empty inner response", func(t *testing.T, s *SecureChannel) []byte {
			return sessionResponse(t, s, encrypt(t, s, pad(nil)))
		}, 2},
		{"truncated inner response", func(t *testing.T, s *SecureChannel) []byte {
			inner := []byte{byte(commands.CommandTypeGenerateAsymmetricKey) + commands.ResponseCommandOffset, 0, 1, 0x12}
			return sessionResponse(t, s, encrypt(t, s, pad(inner)))
		}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestChannel(t, func(s *SecureChannel) []byte { return tt.respond(t, s) })
			resp, err := s.SendEncryptedCommand(echoCommand(t))
			if err == nil {
				t.Fatalf("got %#v, want an error", resp)
			}
			if s.Counter != tt.wantCounter {
				t.Errorf("Counter = %d, want %d", s.Counter, tt.wantCounter)
			}
		})
	}
}
