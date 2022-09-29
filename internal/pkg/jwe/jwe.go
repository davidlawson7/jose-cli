package jwe

import (
	"encoding/base64"
	"strings"

	"github.com/square/go-jose"
)

func GetJWTClaimFromJWE(jweStr string, secret string) (*string, error) {
	jwe, err := jose.ParseEncrypted(jweStr)
	if err != nil {
		return nil, err
		// panic(fmt.Errorf("fatal error, unable to parse jwe: %w", err))
	}

	decryptedJWT, err := jwe.Decrypt(secret)
	if err != nil {
		return nil, err
		// panic(fmt.Errorf("fatal error, unable to decrypt jwe: %w", err))
	}

	// extract the claim from the jwt string (middle base64 string)
	jwtStr := string(decryptedJWT)
	tmp := jwtStr[strings.IndexByte(jwtStr, '.')+1:]
	claimBody := tmp[:strings.IndexByte(tmp, '.')] + "=="

	rawDecodedText, err := base64.StdEncoding.DecodeString(claimBody)
	if err != nil {
		return nil, err
		// panic(fmt.Errorf("fatal error, unable to decode body of jwt: %w", err))
	}
	str := string(rawDecodedText)
	return &str, nil
}
