/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package jwe

import (
	"github.com/containerd/containerd/images/encryption/config"
	"github.com/containerd/containerd/images/encryption/keywrap"
	"github.com/containerd/containerd/images/encryption/utils"
	"github.com/pkg/errors"

	jose "gopkg.in/square/go-jose.v2"
)

type jweKeyWrapper struct {
}

func (kw *jweKeyWrapper) GetAnnotationID() string {
	return "org.opencontainers.image.enc.keys.jwe"
}

// NewKeyWrapper returns a new key wrapping interface using jwe
func NewKeyWrapper() keywrap.KeyWrapper {
	return &jweKeyWrapper{}
}

// WrapKeys wraps the session key for recpients and encrypts the optsData, which
// describe the symmetric key used for encrypting the layer
func (kw *jweKeyWrapper) WrapKeys(ec *config.EncryptConfig, optsData []byte) ([]byte, error) {
	var joseRecipients []jose.Recipient

	err := addPubKeys(&joseRecipients, ec.Parameters["pubkeys"])
	if err != nil {
		return nil, err
	}
	// no recipients is not an error...
	if len(joseRecipients) == 0 {
		return nil, nil
	}

	encrypter, err := jose.NewMultiEncrypter(jose.A256GCM, joseRecipients, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "jose.NewMultiEncrypter failed")
	}
	jwe, err := encrypter.Encrypt(optsData)
	if err != nil {
		return nil, errors.Wrapf(err, "JWE Encrypt failed")
	}
	return []byte(jwe.FullSerialize()), nil
}

func (kw *jweKeyWrapper) UnwrapKey(dc *config.DecryptConfig, jweString []byte) ([]byte, error) {
	jwe, err := jose.ParseEncrypted(string(jweString))
	if err != nil {
		return nil, errors.New("jose.ParseEncrypted failed")
	}

	privKeys := kw.GetPrivateKeys(dc.Parameters)
	if len(privKeys) == 0 {
		return nil, errors.New("No private keys found for JWE decryption")
	}

	for _, privKey := range privKeys {
		key, err := utils.ParsePrivateKey(privKey, "JWE")
		if err != nil {
			return nil, err
		}
		_, _, plain, err := jwe.DecryptMulti(key)
		if err == nil {
			return plain, nil
		}
	}
	return nil, errors.New("JWE: No suitable private key found for decryption")
}

func (kw *jweKeyWrapper) GetPrivateKeys(dcparameters map[string][][]byte) [][]byte {
	return dcparameters["privkeys"]
}

func (kw *jweKeyWrapper) GetKeyIdsFromPacket(b64jwes string) ([]uint64, error) {
	return nil, nil
}

func (kw *jweKeyWrapper) GetRecipients(b64jwes string) ([]string, error) {
	return []string{"[jwe]"}, nil
}

func addPubKeys(joseRecipients *[]jose.Recipient, pubKeys [][]byte) error {
	if len(pubKeys) == 0 {
		return nil
	}
	for _, pubKey := range pubKeys {
		key, err := utils.ParsePublicKey(pubKey, "JWE")
		if err != nil {
			return err
		}

		*joseRecipients = append(*joseRecipients, jose.Recipient{
			Algorithm: jose.RSA_OAEP,
			Key: &jose.JSONWebKey{
				Key: key,
			},
		})
	}
	return nil
}
