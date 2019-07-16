package tunnel

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/ssh"
)

// PemKey is the private key sealed inside an encrypted container.
type PemKey struct {
	*memguard.Enclave
}

// NewPemKey loads a private key from a file and seals it into an encrypted container in memory.
func NewPemKey(keyPath string, passphrase []byte) (*PemKey, error) {
	data, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	keyBlock, err := decodePemKey(data)
	if err != nil {
		return nil, err
	}

	if x509.IsEncryptedPEMBlock(keyBlock) {
		key, err := x509.DecryptPEMBlock(keyBlock, passphrase)
		if err != nil {
			return nil, err
		}
		return &PemKey{memguard.NewEnclave(key)}, nil
	}

	return &PemKey{memguard.NewEnclave(keyBlock.Bytes)}, nil
}

// Signer creates an ssh.Signer object from the sealed private key and returns it.
func (k *PemKey) Signer() (ssh.Signer, error) {
	key, err := k.Open()
	if err != nil {
		return nil, err
	}
	defer key.Destroy()

	signer, err := ssh.ParsePrivateKey(key.Bytes())
	if err != nil {
		return nil, err
	}

	return signer, nil
}

func decodePemKey(data []byte) (*pem.Block, error) {
	p, r := pem.Decode(data)

	if p == nil && len(r) > 0 {
		return nil, fmt.Errorf("error while parsing key: no PEM data found")
	}

	if len(r) != 0 {
		return nil, fmt.Errorf("extra data in encoded key")
	}

	return p, nil
}
