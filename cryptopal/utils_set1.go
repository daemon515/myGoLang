// Implement all simple utils for cryptopals challenge
package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
//	"unicode"
	"bytes"
	"crypto/aes"
//	"crypto/cipher"
)

func ToBase64(hexString string) ([]byte, error) {
	inData, err_ := hex.DecodeString(hexString);
	if (err_ != nil) {
		return nil, err_
	}
	dst := base64.StdEncoding.EncodeToString(inData);
	return []byte(dst), nil
}

func FromBase64(a []byte) ([]byte, error) {
	dst, err:= base64.StdEncoding.DecodeString(string(a));
	return dst, err
}


func AxorB(a []byte, b []byte) ([]byte, error) {
	if ((len(a) == 0) || (len(b) == 0)) {
		return []byte(""), errors.New("Empty string")
	}

	// XoR requires both a and b to be of same length
	dLen := len(a)
	if (dLen < len(b)) {
		dLen = len(b)
	}

	dst := make([]byte, dLen);
	//fmt.Println(dLen, a, b);
	for i:=0; i < dLen; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return dst, nil
}

func scoreAttempt(inBytes []byte) (float32, int) {
	// score based on number of % of bytes being alphanumeric, space
	bLen := len(inBytes)
	var score float32;
	var noscore int;
	if (bLen == 0) {
		return 0, 0;
	}

	// https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
	var LetterFrequencies = map[string]float32{
		"a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702,
		"f": 2.228, "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153,
		"k": 0.772, "l": 4.025, "m": 2.406, "n": 6.749, "o": 7.507,
		"p": 1.929, "q": 0.095, "r": 5.987, "s": 6.327, "t": 9.056,
		"u": 2.758, "v": 2.360, "x": 0.150, "y": 1.974, "z": 0.074,
		" ": 13.0, // space is slightly more frequent than (e)
	}
	for _, r := range inBytes {
		if 'A' <= r && r <= 'Z' {
			r = r + ('a' - 'A')
		}
		s := LetterFrequencies[string(r)];
		if (s > 0) {
			score += LetterFrequencies[string(r)];
		} else {
			noscore += 1
		}
	}
	// for _, r := range inBytes {
	// 	//etaoin shrdlu
	// 	//if (r == ' ') {
	// 	if ((r == 'e' || r == 't' || r == 'a' || r == 'o' || r == 'i' || r == 'n' || r == ' ' || r == 's' || r == 'h' || r == 'r') ||
	// 		 (r == 'd' || r == 'l' || r == 'u' || r == 'E' || r == 'T' || r == 'A' || r == 'O' || r == 'I' || r == 'N') ||
	// 		 (r == 'S' || r == 'H' || r == 'R' || r == 'D' || r == 'L' || r == 'U')) {
	// 	//if ((r > 'a' && r < 'z') || (r > 'A' && r < 'Z') || (r == ' ') || (r == '\'')) {
	// 		score = alphaLen + 1;
	// 	}
	// }
	return score, noscore;
}

func BreakSingleByteXoRCipher(inBytes []byte) (string, float32, byte) {
	var decrypted []byte;
	inLen := len(inBytes);
	bestIndex := 0
	scoreList := make([]float32, 256)
	for i := 0; i < 256; i++ {
		mask := bytes.Repeat([]byte{byte(i)}, inLen);
		dc, _ := AxorB(inBytes, mask);
		score, _ := scoreAttempt(dc)
		scoreList[i] = score
		if (i == 0 || scoreList[i] > scoreList[bestIndex]) {
			bestIndex = i;
			decrypted = dc;
		}
	}
	//fmt.Printf("Best score is %d at index %d\n", scoreList[bestIndex], bestIndex);
	//fmt.Printf("Key: %d Decrypt: %s", bestIndex, decrypted);
	return string(decrypted), float32(scoreList[bestIndex]), byte(bestIndex);
}

func EncryptRepeatingKeyXoRCipher(inString string, key string) (string) {
	textBytes := []byte(inString);
	keyBytes := []byte(key);
	fmt.Println(keyBytes)
	fmt.Println(textBytes)

	result := make([]byte, len(textBytes));
	for i := 0; i < len(textBytes); i++ {
		result[i] = textBytes[i] ^ keyBytes[i % len(keyBytes)]
	}

	dst := make([]byte, hex.EncodedLen(len(result)))
	hex.Encode(dst, result)
	return string(dst);
}

func DecryptRepeatingKeyXoRCipher(in []byte, key []byte) ([]byte) {
	plain := make([]byte, len(in))
	for i:=0; i<len(in); i++ {
		plain[i] = in[i] ^ key[i%len(key)]
	}
	return plain
}

func HammingDistance(a []byte, b []byte) int {
	minlen := len(a)
	rem := 0;
	if (len(b) < minlen) {
		minlen = len(b)
		rem = len(a) - len(b)
	} else {
		rem = len(b) - len(a)
	}
	dist := 0;
	for i := 0; i < minlen; i++ {
		r := a[i] ^ b[i]
		for j := 0; j < 8; j++ {
			if (r & 0x1 == 0x1) {
				dist += 1
			}
			r = r >> 1;
		}
	}

	if (rem > 0) {
		dist += (rem * 8)
	}
	return dist
}

func DecryptAES128_ECBMode(ciphertext []byte, key []byte) ([]byte) {
	var plaintext []byte
	block, err := aes.NewCipher(key)
	if (err != nil) {
		fmt.Println("Error %v\n", err)
		return plaintext
	}
	if (len(ciphertext) < aes.BlockSize) {
		fmt.Printf("Invalid ciphertext size\n")
		return plaintext
	}
	if (len(ciphertext) % aes.BlockSize != 0) {
		fmt.Printf("Invalid ciphertext block size\n")
		return plaintext	
	}

	plaintext = make([]byte, 0)
	numBlocks := len(ciphertext) / len(key)
	for i:=0;i<numBlocks;i++ {
		dc := make([]byte, len(key))
		ctxt := ciphertext[i*len(key) : (i+1)*len(key)]
		block.Decrypt(dc, ctxt)
		plaintext = append(plaintext, dc...)
	}

	return plaintext;
}