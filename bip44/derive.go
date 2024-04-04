package bip44

import (
	"fmt"
	"hdwallet/bip32"
	"strconv"
	"strings"
)

const (
	HardenedKeyStart = 0x80000000 // 2^31
)

// BIP44 경로에 따른 키 파생
func DeriveKeyFromPath(masterKey *bip32.Key, path string) (*bip32.Key, error) {
	if !strings.HasPrefix(path, "m/") {
		return nil, fmt.Errorf("invalid path: must start with 'm/'")
	}

	segments := strings.Split(path, "/")[1:] // "m" 세그먼트 제거
	if len(segments) < 3 {
		return nil, fmt.Errorf("invalid path: too short for BIP44")
	}

	var key = masterKey
	for _, segment := range segments {
		index, hardened, err := parsePathSegment(segment)
		if err != nil {
			return nil, err
		}

		if hardened {
			index += HardenedKeyStart
		}

		key, err = key.NewChildKey(index)
		if err != nil {
			return nil, fmt.Errorf("error deriving key for segment '%s': %v", segment, err)
		}
	}

	return key, nil
}

// parsePathSegment는 경로 세그먼트를 분석하여 인덱스와 하드닝 여부를 반환
func parsePathSegment(segment string) (uint32, bool, error) {
	hardened := strings.HasSuffix(segment, "'")
	if hardened {
		segment = strings.TrimSuffix(segment, "'")
	}

	index, err := strconv.ParseUint(segment, 10, 32)
	if err != nil {
		return 0, false, fmt.Errorf("invalid path segment '%s': %v", segment, err)
	}

	return uint32(index), hardened, nil
}
