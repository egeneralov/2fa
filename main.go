package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	homedir "github.com/mitchellh/go-homedir"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	configFilePath string
	configBytes    []byte
	config         = []ConfigurationItem{}
	home           string
	issuers        []string

	err error
)

func main() {
	home, err = homedir.Dir()
	if err != nil {
		panic(err)
	}

	configFilePath = os.Getenv("TWO_FA_CONFIG")
	if configFilePath == "" {
		configFilePath = home + "/.2faconfig.yaml"
	}

	flag.StringVar(&configFilePath, "config", configFilePath, "path to secret file")
	flag.Parse()

	configBytes, err = ioutil.ReadFile(configFilePath)
	if err != nil {
		fmt.Println("configuration file read error")
		panic(err)
	}
	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		panic(err)
	}

	for _, n := range config {
		issuers = append(issuers, n.Issuer)
	}

	count := flag.NArg()

	if count == 0 {
		fmt.Println(issuers)
		flag.Usage()
		// 		flag.PrintDefaults()
		os.Exit(1)
	}

	if count != 1 {
		fmt.Println(issuers)
		flag.Usage()
		// 		flag.PrintDefaults()
		os.Exit(1)
	}

	Issuer, err := getIssuerFromFlags()
	if err != nil {
		panic(err)
	}

	for _, n := range config {
		if strings.ToLower(Issuer) == strings.ToLower(n.Issuer) {
			fmt.Println(getTOTPToken(n.Secret))
		}
	}
}

func getIssuerFromFlags() (string, error) {
	for _, val := range flag.Args() {
		return val, nil
	}
	return "", fmt.Errorf("why you appear here?")
}

type ConfigurationItem struct {
	Issuer string
	Secret string
}

// below code was founded here: https://github.com/tilaklodha/google-authenticator/blob/master/google_authenticator.go
func getTOTPToken(secret string) string {
	interval := time.Now().Unix() / 30
	return getHOTPToken(secret, interval)
}

func getHOTPToken(secret string, interval int64) string {
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		panic(err)
	}
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(interval))
	hash := hmac.New(sha1.New, key)
	hash.Write(bs)
	h := hash.Sum(nil)
	o := (h[19] & 15)

	var header uint32
	r := bytes.NewReader(h[o : o+4])
	err = binary.Read(r, binary.BigEndian, &header)

	if err != nil {
		panic(err)
	}
	h12 := (int(header) & 0x7fffffff) % 1000000
	otp := strconv.Itoa(int(h12))
	return prefixWithZeros(otp)
}

func prefixWithZeros(otp string) string {
	if len(otp) == 6 {
		return otp
	}
	for i := (6 - len(otp)); i > 0; i-- {
		otp = "0" + otp
	}
	return otp
}
