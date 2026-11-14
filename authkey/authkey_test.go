package authkey

import (
	"encoding/hex"
	"testing"
)

func TestFromPasswordDefaultKey(t *testing.T) {
	// The YubiHSM 2 factory auth key 1 is derived from the password "password".
	k, err := FromPassword("password")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(k.GetEncKey()); got != "090b47dbed595654901dee1cc655e420" {
		t.Errorf("enc key = %s", got)
	}
	if got := hex.EncodeToString(k.GetMacKey()); got != "592fd483f759e29909a04c4505d2ce0a" {
		t.Errorf("mac key = %s", got)
	}
}
