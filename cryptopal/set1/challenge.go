// Implement challenge set1 simple utils for cryptopals challenge
package main

import (
	"bufio"
	"io"
	"os"
	"log"
	"fmt"
	"bytes"
 	"github.com/daemon515/myGoLang/cryptopal"
)

func challenge4() {
	file, err := os.Open("1.4.txt");
	if (err != nil) {
		log.Fatal(err);
	}
	defer file.Close();

	reader := bufio.NewReader(file);

	var result string
	var best_score float32 = 0
	i := 0
	for ;; {
		line, err := reader.ReadBytes(0xA)
		i = i + 1
		if (len(line) > 1) {
			line = bytes.TrimSuffix(line,[] byte{0xA});
			res, score, b := cryptopals.BreakSingleByteXoRCipher(line);
			fmt.Printf("%d: %d: %v: %d: %s\n", i, len(line), b, len(res), res);
			if (score > best_score) {
				result = res
				best_score = score
			}
		}
		if (err == io.EOF) {
			break;
		} else if (err != nil) {
			log.Fatal(err);
		}
	}
	fmt.Printf("Final Result: %s",result)
}

func guessKeySize(buf []byte) int {
	var leastDist float32
	var soln int;
	var avg float32;
	var distance int;
	for i:=2; i < 40; i++ {
		numBlocks := len(buf) / i;
		distance = 0;
		for j:=1;j<numBlocks;j++ {
			blockA := buf[((j-1)*i):(j*i)]
			blockB := buf[(j*i):((j+1)*i)]
			distance += cryptopals.HammingDistance(blockA, blockB)
		}

		avg = float32(distance) / float32(numBlocks*i)
		//fmt.Printf("%d %F\n", i, avg)
		if (i == 2) {
			leastDist = avg
			soln = i
		} else {
			if (leastDist > avg) {
				leastDist = avg;
				soln = i
			}
		}
	}
	return soln
}

func solveForSize(buf []byte, sz int) ([]byte){
	var block []byte;
	var key []byte;
	for i:=0; i < sz; i++ {
		block = make([]byte, 0)
		for j:=i; j < len(buf); j=j+sz {
			block = append(block, buf[j])
		}
		_, _, b := cryptopals.BreakSingleByteXoRCipher(block);
		key = append(key, b)
		//fmt.Printf("BlockLen %d : %d score %F, byte %c, len %d\n", len(block), i, score, b, len(res));
	}
	return key
}

func fileRead(filename string) []byte {
	var content []byte

	file, err := os.Open(filename);
	if (err != nil) {
		log.Fatal(err);
		return content
	}
	defer file.Close();


	stat, err := file.Stat()
	fmt.Printf("File size %d\n", stat.Size())

	if (err != nil) {
		log.Fatal(err)
		return content
	}
	scanner := bufio.NewScanner(file);
	for scanner.Scan() {
		line := []byte(scanner.Text())
		//line = bytes.TrimSuffix(line,[] byte{0xA});
		//fmt.Printf("%s", line);
		content = append(content, line...)
	}
	return content;
}

func challenge6() {
	content := fileRead("1.6.txt");
	//fmt.Println();
	decoded, _ := cryptopals.FromBase64(content);
	soln := guessKeySize(decoded);
	fmt.Printf("Best KeySize = %d\n", soln)
	key := solveForSize(decoded, soln)
	fmt.Printf("Key: %s\n", string(key))
	// Decrypt the input text
	plainText := cryptopals.DecryptRepeatingKeyXoRCipher(decoded, key)
	fmt.Printf("PlainText:\n%s\n", string(plainText))
}

func challenge7() {
	content := fileRead("1.7.txt");
	decoded, _ := cryptopals.FromBase64(content);
	plainText := cryptopals.DecryptAES128_ECBMode(decoded, []byte("YELLOW SUBMARINE"))
	fmt.Printf("PlainText:\n%s\n", string(plainText))
}

func main() {
	//challenge4();
	//challenge6();
	challenge7();
}
