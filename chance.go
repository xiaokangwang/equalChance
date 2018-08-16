package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"sort"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

func main() {
	if len(os.Args) == 1 {
		//generate token
		out, _ := GenerateRandomString(32)
		fmt.Println(out)
		hout := hashstring(out)
		fmt.Printf("%x\n", hout)
		return
	}
	token := os.Args[1]
	hout := hashstring(token)
	fmt.Printf("%x\n", hout)
	players := make([]Player, 0)
	csvin := csv.NewReader(os.Stdin)
	//Ignore header
	_, err := csvin.Read()
	if err != nil {
		panic(err)
	}
	for {
		item, err := csvin.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}

		pl := Player{Name: item[0], Nonce: item[1]}
		hash := sha3.New224()
		hash.Write([]byte(pl.Nonce))
		pl.Score = hash.Sum([]byte(token))
		pl.Score, err = scrypt.Key([]byte(pl.Score), []byte("equalChance"), 32768, 8, 1, 16)
		if err != nil {
			panic(err)
		}
		players = append(players, pl)
	}
	sort.Sort(PlayerG(players))
	for index, in := range players {
		fmt.Printf("%v %v %v %x\n", index, in.Name, in.Nonce, in.Score)
	}

}

type Player struct {
	Name  string
	Nonce string
	Score []byte
}
type PlayerG []Player

func (s PlayerG) Less(i, j int) bool {

	return bytes.Compare(s[i].Score, s[j].Score) < 0
}

func (s PlayerG) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s PlayerG) Len() int {
	return len(s)
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomString returns a URL-safe, base64 encoded
// securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

func hashstring(input string) []byte {
	hash := sha3.New224()
	out := hash.Sum([]byte(input))
	var err error
	out, err = scrypt.Key([]byte(out), []byte("equalChanceKey"), 32768, 16, 1, 16)
	if err != nil {
		panic(err)
	}
	return out
}
