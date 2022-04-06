package main

import (
	"errors"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

func GetDecodedPrivateKeyWithSHA512PW(armouredPrivateKey string, password string) (string, error){
	return unlockPrivatePGPKey(armouredPrivateKey, password)
}

func GetDecodedPrivateKeyWithPlainTextPW(armouredPrivateKey string, password string) (string, error) {
	hashedPassword := SHA512HashEncode(password)
	return unlockPrivatePGPKey(armouredPrivateKey, hashedPassword)
}

func unlockPrivatePGPKey(armouredPrivateKey string, password string) (string, error) {
	privateKeyObj, err := crypto.NewKeyFromArmored(armouredPrivateKey)
	if !privateKeyObj.IsPrivate() {
		return "", errors.New("the key you are trying to unlock is not a private one")
	}
	if err != nil {
		return "", err
	}
	hashedString := password[32:]
	unlockedKeyObj, err := privateKeyObj.Unlock([]byte(hashedString))
	if err != nil {
		return "", err
	}
	armouredKey, err := unlockedKeyObj.Armor()
	if err != nil {
		return "", err
	}
	return armouredKey, nil
}
