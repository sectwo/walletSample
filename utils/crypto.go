package utils

import (
	"encoding/hex"
	"fmt"
	"hdwallet/bip32"
)

func KeyToString(key *bip32.Key) string {
	if key.IsPrivate {
		// 비공개 키를 HEX 문자열로 변환
		privKeyHex := hex.EncodeToString(key.Key)
		chainCodeHex := hex.EncodeToString(key.ChainCode)
		return fmt.Sprintf("Private Key: %s\nChain Code: %s", privKeyHex, chainCodeHex)
	} else {
		// 공개 키를 HEX 문자열로 변환 (공개 키 파생 구현이 필요)
		pubKeyHex := hex.EncodeToString(key.Key) // 공개 키 변환 예시
		chainCodeHex := hex.EncodeToString(key.ChainCode)
		return fmt.Sprintf("Public Key: %s\nChain Code: %s", pubKeyHex, chainCodeHex)
	}
}
