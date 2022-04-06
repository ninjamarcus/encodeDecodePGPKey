package main

import (
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

type Keys struct {
	Public         string
	EncodedPrivate string
	Password       string
}

func GetNewPGPKeysWithSHA512PW(username string, password string, email string) (*Keys, error) {
	return generatePGPKeys(username, password, email)

}
func GetNewPGPKeysWithPlainTextPW(username, password string, email string) (*Keys, error) {
	hashedPassword := SHA512HashEncode(password)
	return generatePGPKeys(username, hashedPassword, email)

}

func generatePGPKeys(username string, password string, email string) (*Keys, error) {
	hashString := password[32:]
	ecKey, err := crypto.GenerateKey(username, email, "x25519", 0)
	locked, err := ecKey.Lock([]byte(hashString))
	if err != nil {
		return nil, err
	}
	publicKey, err := ecKey.GetArmoredPublicKey()
	if err != nil {
		return nil, err
	}
	lockedPrivateKey, err := locked.Armor()
	if err != nil {
		return nil, err
	}
	return &Keys{
		Public:         publicKey,
		EncodedPrivate: lockedPrivateKey,
		///todo: remove the password as we dont need to be handing it about it was here for testing.
		Password: password,
	}, nil
}
