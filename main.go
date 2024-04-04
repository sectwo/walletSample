package main

import (
	"fmt"
	"hdwallet/bip32"
	"hdwallet/bip39"
	"hdwallet/bip44"
	"hdwallet/utils"
)

func main() {
	// BIP39 니모닉 코드 생성
	language := "english" // 사용할 언어 설정
	byteSize := 32        // 엔트로피 비트 사이즈 설정 (256비트 권장)
	mnemonic := bip39.GenerateMnemonicCode(language, byteSize)
	fmt.Println("Generated Mnemonic:", mnemonic)

	// 니모닉 코드로부터 시드 생성
	password := "isaac1234" // 사용자가 입력한 암호
	seed := bip39.Seed(mnemonic, password)
	fmt.Println("Generated Seed:", seed)

	// BIP32 마스터 키 생성
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		fmt.Println("Error generating master key:", err)
		return
	}
	fmt.Printf("Master Key: %+v\n", masterKey)

	// BIP44: 마스터 키로부터 특정 자식 키 파생
	// 예: Bitcoin, 계정 0, 외부 체인, 주소 인덱스 0
	path := "m/44'/0'/0'/0/0"
	childKey, err := bip44.DeriveKeyFromPath(masterKey, path)
	if err != nil {
		fmt.Println("Error deriving child key:", err)
		return
	}
	fmt.Println("Child Key:", childKey)
	keyString := utils.KeyToString(childKey)
	fmt.Println(keyString)
}
