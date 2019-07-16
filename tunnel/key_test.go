package tunnel

import (
	"crypto/x509"
	"fmt"
	"testing"
)

func TestPemKey(t *testing.T) {
	tests := []struct {
		keyPath    string
		encrypted  bool
		passphrase []byte
	}{
		{
			"testdata/dotssh/id_rsa",
			false,
			[]byte{},
		},
		{
			"testdata/dotssh/id_rsa_encrypted",
			true,
			[]byte("mole"),
		},
	}

	for _, test := range tests {
		key, err := NewPemKey(test.keyPath, test.passphrase)
		if err != nil {
			t.Errorf("test failed for key %s: %v", test.keyPath, err)
		}

		opened, err := key.Open()
		if err != nil {
			t.Error(err)
		}
		fmt.Println(opened.Bytes())
		block, err := decodePemKey(opened.Bytes())
		if err != nil {
			t.Error(err)
		}
		opened.Destroy()

		if x509.IsEncryptedPEMBlock(block) != false {
			t.Error("key should be decrypted")
		}

		_, err = key.Signer()
		if err != nil {
			t.Errorf("test failed for key %s: %v", test.keyPath, err)
		}
	}
}
