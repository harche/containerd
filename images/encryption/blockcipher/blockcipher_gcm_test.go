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

package blockcipher

import (
	"testing"
)

func TestBlockCipherAesGcmCreateValid(t *testing.T) {
	_, err := NewGCMLayerBlockCipher(128)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewGCMLayerBlockCipher(256)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBlockCipherAesGcmCreateInvalid(t *testing.T) {
	_, err := NewGCMLayerBlockCipher(8)
	if err == nil {
		t.Fatal(err)
	}
	_, err = NewGCMLayerBlockCipher(255)
	if err == nil {
		t.Fatal(err)
	}
}

func TestBlockCipherAesGcmEncryption(t *testing.T) {
	var (
		symKey []byte                  = []byte("01234567890123456789012345678912")
		opt    LayerBlockCipherOptions = LayerBlockCipherOptions{
			SymmetricKey: symKey,
		}
		layerData []byte = []byte("this is some data")
	)

	bc, err := NewGCMLayerBlockCipher(256)
	ciphertext, lbco, err := bc.Encrypt(layerData, opt)
	if err != nil {
		t.Fatal(err)
	}

	// Use a different instantiated object to indicate an invokation at a diff time
	bc2, err := NewGCMLayerBlockCipher(256)
	plaintext, _, err := bc2.Decrypt(ciphertext, lbco)
	if err != nil {
		t.Fatal(err)
	}

	if string(plaintext) != string(layerData) {
		t.Fatal("Decrypted data is incorrect")
	}
}

func TestBlockCipherAesGcmEncryptionInvalidKey(t *testing.T) {
	var (
		symKey []byte                  = []byte("01234567890123456789012345678912")
		opt    LayerBlockCipherOptions = LayerBlockCipherOptions{
			SymmetricKey: symKey,
		}
		layerData []byte = []byte("this is some data")
	)

	bc, err := NewGCMLayerBlockCipher(256)
	ciphertext, lbco, err := bc.Encrypt(layerData, opt)
	if err != nil {
		t.Fatal(err)
	}

	// Use a different instantiated object to indicate an invokation at a diff time
	bc2, err := NewGCMLayerBlockCipher(256)
	lbco.SymmetricKey = []byte("aaa34567890123456789012345678912")
	_, _, err = bc2.Decrypt(ciphertext, lbco)
	if err == nil {
		t.Fatal(err)
	}
}

func TestBlockCipherAesGcmEncryptionInvalidKeyLength(t *testing.T) {
	var (
		symKey []byte                  = []byte("012345")
		opt    LayerBlockCipherOptions = LayerBlockCipherOptions{
			SymmetricKey: symKey,
		}
		layerData []byte = []byte("this is some data")
	)

	bc, err := NewGCMLayerBlockCipher(256)
	_, _, err = bc.Encrypt(layerData, opt)
	if err == nil {
		t.Fatal(err)
	}
}
