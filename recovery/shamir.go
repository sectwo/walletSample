package recovery

import (
	"github.com/hashicorp/vault/shamir"
)

// SplitKey 함수는 주어진 키를 지정된 수의 파트로 나누며, 최소 복구 파트 수도 지정할 수 있음
func SplitKey(secret []byte, parts, minParts int) ([][]byte, error) {
	return shamir.Split(secret, parts, minParts)
}

// CombineParts 함수는 나누어진 키 파트들을 결합하여 원래의 키를 복구
func CombineParts(parts [][]byte) ([]byte, error) {
	return shamir.Combine(parts)
}
