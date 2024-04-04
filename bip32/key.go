package bip32

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
)

const (
	FirstHardenedChild        = uint32(0x80000000)
	PublicKeyCompressedLength = 33
)

type Key struct {
	Key         []byte // 33 bytes
	ChainCode   []byte // 32 bytes
	Depth       byte   // 1 byte
	ParentFP    []byte // 4 bytes, 부모 키의 지문
	ChildNumber []byte // 4 bytes
	IsPrivate   bool   // 비공개 키 여부
}

func NewMasterKey(seed []byte) (*Key, error) {
	if len(seed) < 16 || len(seed) > 64 {
		return nil, errors.New("seed length must be between 16 and 64 bytes")
	}

	hmac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	hmac.Write(seed)
	I := hmac.Sum(nil)
	IL, IR := I[:32], I[32:]

	key := &Key{
		Key:         IL,
		ChainCode:   IR,
		Depth:       0,
		ParentFP:    []byte{0, 0, 0, 0},
		ChildNumber: []byte{0, 0, 0, 0},
		IsPrivate:   true,
	}

	return key, nil
}

func (k *Key) NewChildKey(index uint32) (*Key, error) {
	var data []byte
	if index >= FirstHardenedChild {
		if !k.IsPrivate {
			return nil, errors.New("cannot derive a hardened key from a public key")
		}
		// 하드웨어된 자식 키: 0x00 + 부모 비공개 키 + 인덱스
		data = append([]byte{0x0}, k.Key...)
	} else {
		// 일반 자식 키: 부모 공개 키 + 인덱스
		// 여기서는 간단히 부모 키를 그대로 사용하며, 실제로는 공개 키를 계산 필요
		data = k.Key
	}
	data = append(data, uint32ToByte(index)...)

	hmac := hmac.New(sha512.New, k.ChainCode)
	hmac.Write(data)
	I := hmac.Sum(nil)
	IL, IR := I[:32], I[32:]

	childKey := &Key{
		Key:         IL,
		ChainCode:   IR,
		Depth:       k.Depth + 1,
		ParentFP:    k.Fingerprint(), // 부모 키의 지문 계산
		ChildNumber: uint32ToByte(index),
		IsPrivate:   k.IsPrivate,
	}

	return childKey, nil
}

func uint32ToByte(i uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], i)
	return b[:]
}

func (k *Key) Fingerprint() []byte {
	// 여기서는 간단히 키의 첫 4바이트를 사용
	// 실제로는 RIPEMD160(SHA256(공개키))의 앞 4바이트를 사용해야 함
	return k.Key[:4]
}

func (k *Key) Serialize() ([]byte, error) {
	// 예시로 간단한 직렬화 로직을 구현
	// 실제 구현에서는 더 많은 검증과 안전한 직렬화 방법이 필요
	var b []byte
	b = append(b, k.Depth)
	b = append(b, k.ParentFP...)
	b = append(b, k.ChildNumber...)
	b = append(b, k.ChainCode...)
	b = append(b, k.Key...)
	return b, nil
}

func Deserialize(data []byte) (*Key, error) {
	// 예시로 간단한 역직렬화 로직을 구현
	// 실제 구현에서는 더 많은 검증과 안전한 역직렬화 방법이 필요
	if len(data) < 78 {
		return nil, errors.New("data too short")
	}
	key := &Key{
		Depth:       data[0],
		ParentFP:    data[1:5],
		ChildNumber: data[5:9],
		ChainCode:   data[9:41],
		Key:         data[41:78],
		IsPrivate:   true, // 이 예시에서는 모든 키를 비공개 키로 가정
	}
	return key, nil
}
