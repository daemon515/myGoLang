// Implement all test for utils.go
package cryptopals

import (
	"testing"
	"bytes"
	"encoding/hex"
)

func TestToBase64(t *testing.T) {
	cases := []struct {
		in string
		want string
	}{
		{"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
		 "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"},
	}
	for _, c := range cases {
		got, _ := ToBase64(c.in)
		if string(got) != c.want {
			t.Errorf("ToBase64(%q) == %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAxorB(t *testing.T) {
	cases := []struct {
		in1, in2 string
		want string
	}{
		{"4040", "4040", "0000"},
		{"1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965", "746865206b696420646f6e277420706c6179"},
	}
	for _, c := range cases {
		in1, err_ := hex.DecodeString(c.in1);
		if (err_ != nil) {
			t.Errorf("hex.DecodeString(%q) failed", c.in1)
		}
		in2, err_ := hex.DecodeString(c.in2);
		if (err_ != nil) {
			t.Errorf("hex.DecodeString(%q) failed", c.in2)
		}

		got, err := AxorB(in1, in2)
		want, _ := hex.DecodeString(c.want);
		if (err != nil) {
			t.Errorf("AxorB(%q, %q) returned %q", c.in1, c.in2, err)
		} else if (false == bytes.Equal(got, want)) {
			t.Errorf("AxorB(%q, %q) == %q, want %q", c.in1, c.in2, got, c.want)
		}
	}
}

func TestDecryptSingleByteXoRCipher(t *testing.T) {
	cases := []struct {
		in string
		want string
	}{
		{"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", "Cooking MC's like a pound of bacon",},
	}
	for _, c := range cases {
		in, _ := hex.DecodeString(c.in);
		got, _, _ := BreakSingleByteXoRCipher(in)
		if (got != c.want) {
			t.Errorf("Decrypt(%q, %q) == %q, want %q", c.in, got, c.want)
		}
	}
}


func TestEncryptRepeatingKeyXoRCipher(t *testing.T) {
	cases := []struct {
		in string
		want string
	}{
{`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`,
`0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`},
	}
	for _, c := range cases {
		got := EncryptRepeatingKeyXoRCipher(c.in, "ICE")
		if (got != c.want) {
			t.Errorf("Encrypt(%s) == %s, want %q", c.in, got, c.want)
		}
	}
}

func TestHammingDistance(t *testing.T) {
	cases := []struct {
		inA string
		inB string
		want int
	}{
		{"this is a test", "wokka wokka!!!", 37},
	}
	for _, c := range cases {
		got := HammingDistance([]byte(c.inA), []byte(c.inB))
		if (got != c.want) {
			t.Errorf("HammingDistance(%s, %s) == %d, want %d", c.inA, c.inB, got, c.want)
		}
	}
}