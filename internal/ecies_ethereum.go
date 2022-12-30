// Copyright (c) 2013 Kyle Isom <kyle@tyrfingr.is>
// Copyright (c) 2012 The Go Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// This is forked from:
// https://github.com/ethereum/go-ethereum/blob/02cea2330d6b4822b43a7fbaeacc12ddc8e8b1db/crypto/ecies/ecies.go
// to work with both local private keys and pcks11 based keys

package internal

import (
	"crypto"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/binary"
	"hash"

	"github.com/ThalesIgnite/crypto11"
	"github.com/umbracle/ecies"
)

type PrivateKey interface {
	GenerateShared(pub *ecies.PublicKey, skLen, macLen int) (sk []byte, err error)
	Public() *ecies.PublicKey
}

// PrivateKeyLocal is a representation of an elliptic curve private key.
type PrivateKeyLocal struct {
	*ecies.PrivateKey
}

// Import an ECDSA private key as an ECIES private key.
func ImportECDSA(prv *ecdsa.PrivateKey) *PrivateKeyLocal {
	return &PrivateKeyLocal{ecies.ImportECDSA(prv)}
}

func (prv *PrivateKeyLocal) GenerateShared(pub *ecies.PublicKey, skLen, macLen int) (sk []byte, err error) {
	return prv.PrivateKey.GenerateShared(pub, skLen, macLen)
}

func (prv *PrivateKeyLocal) Public() *ecies.PublicKey {
	return &prv.PublicKey
}

type PrivateKeyPkcs11 struct {
	*ecies.PublicKey
	ctx    *crypto11.Context
	signer crypto11.Signer
}

func ImportPcks11(ctx *crypto11.Context, privKey crypto.PrivateKey) *PrivateKeyPkcs11 {
	signer := privKey.(crypto11.Signer)
	pub := signer.Public().(*ecdsa.PublicKey)
	return &PrivateKeyPkcs11{ecies.ImportECDSAPublic(pub), ctx, signer}
}

func (prv *PrivateKeyPkcs11) GenerateShared(pub *ecies.PublicKey, skLen, macLen int) (sk []byte, err error) {
	return prv.ctx.ECDH1Derive(prv.signer, pub.ExportECDSA())
}

func (prv *PrivateKeyPkcs11) Public() *ecies.PublicKey {
	return prv.PublicKey
}

// NIST SP 800-56 Concatenation Key Derivation Function (see section 5.8.1).
func concatKDF(hash hash.Hash, z, s1 []byte, kdLen int) []byte {
	counterBytes := make([]byte, 4)
	k := make([]byte, 0, roundup(kdLen, hash.Size()))
	for counter := uint32(1); len(k) < kdLen; counter++ {
		binary.BigEndian.PutUint32(counterBytes, counter)
		hash.Reset()
		if _, err := hash.Write(counterBytes); err != nil {
			return nil
		}
		if _, err := hash.Write(z); err != nil {
			return nil
		}
		if _, err := hash.Write(s1); err != nil {
			return nil
		}
		k = hash.Sum(k)
	}
	return k[:kdLen]
}

// roundup rounds size up to the next multiple of blocksize.
func roundup(size, blocksize int) int {
	return size + blocksize - (size % blocksize)
}

// deriveKeys creates the encryption and MAC keys using concatKDF.
func deriveKeys(hash hash.Hash, z, s1 []byte, keyLen int) (Ke, Km []byte) {
	K := concatKDF(hash, z, s1, 2*keyLen)
	if K == nil {
		return nil, nil
	}
	Ke = K[:keyLen]
	Km = K[keyLen:]
	hash.Reset()
	if _, err := hash.Write(Km); err != nil {
		return nil, nil
	}
	Km = hash.Sum(Km[:0])
	return Ke, Km
}

// messageTag computes the MAC of a message (called the tag) as per
// SEC 1, 3.5.
func messageTag(hash func() hash.Hash, km, msg, shared []byte) []byte {
	mac := hmac.New(hash, km)
	if _, err := mac.Write(msg); err != nil {
		return nil
	}
	if _, err := mac.Write(shared); err != nil {
		return nil
	}
	tag := mac.Sum(nil)
	return tag
}

// symDecrypt carries out CTR decryption using the block cipher specified in
// the parameters
func symDecrypt(params *ecies.ECIESParams, key, ct []byte) (m []byte, err error) {
	c, err := params.Cipher(key)
	if err != nil {
		return
	}

	ctr := cipher.NewCTR(c, ct[:params.BlockSize])

	m = make([]byte, len(ct)-params.BlockSize)
	ctr.XORKeyStream(m, ct[params.BlockSize:])
	return
}

// Decrypt decrypts an ECIES ciphertext.
func EciesDecrypt(prv PrivateKey, c, s1, s2 []byte) (m []byte, err error) {
	if len(c) == 0 {
		return nil, ecies.ErrInvalidMessage
	}
	pub := prv.Public()
	params := pub.Params
	if params == nil {
		if params = ecies.ParamsFromCurve(pub.Curve); params == nil {
			return nil, ecies.ErrUnsupportedECIESParameters
		}
	}
	hash := params.Hash()

	var (
		rLen   int
		hLen   int = hash.Size()
		mStart int
		mEnd   int
	)

	switch c[0] {
	case 2, 3, 4:
		rLen = (pub.Curve.Params().BitSize + 7) / 4
		if len(c) < (rLen + hLen + 1) {
			return nil, ecies.ErrInvalidMessage
		}
	default:
		return nil, ecies.ErrInvalidPublicKey
	}

	mStart = rLen
	mEnd = len(c) - hLen

	R := new(ecies.PublicKey)
	R.Curve = pub.Curve
	R.X, R.Y = elliptic.Unmarshal(R.Curve, c[:rLen])
	if R.X == nil {
		return nil, ecies.ErrInvalidPublicKey
	}
	if !R.Curve.IsOnCurve(R.X, R.Y) {
		err = ecies.ErrInvalidCurve
		return
	}

	z, err := prv.GenerateShared(R, params.KeyLen, params.KeyLen)
	if err != nil {
		return nil, err
	}
	Ke, Km := deriveKeys(hash, z, s1, params.KeyLen)
	if Ke == nil || Km == nil {
		return nil, ecies.ErrInvalidPublicKey
	}

	d := messageTag(params.Hash, Km, c[mStart:mEnd], s2)
	if d == nil {
		return nil, ecies.ErrInvalidMessage
	}
	if subtle.ConstantTimeCompare(c[mEnd:], d) != 1 {
		return nil, ecies.ErrInvalidMessage
	}

	return symDecrypt(params, Ke, c[mStart:mEnd])
}
