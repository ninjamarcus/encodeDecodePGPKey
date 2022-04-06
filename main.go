package main

import (
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

func main() {
	key, _ := GetNewPGPKeysWithPlainTextPW("mark", "passwprd", "email@email.com")
	decodedKey, err := GetDecodedPrivateKeyWithPlainTextPW(key.EncodedPrivate, "passwprd")
	if err != nil {
		panic(err)
	}
	encodedMSG, _ := helper.EncryptMessageArmored(key.Public, "hello world")
	println(encodedMSG)

	privateKeyObj, err := crypto.NewKeyFromArmored(decodedKey)
	privateKeyRing, err := crypto.NewKeyRing(privateKeyObj)

	msg, err := crypto.NewPGPMessageFromArmored(encodedMSG)

	if err != nil {
		panic(err)
	}
	decrypted, err := privateKeyRing.Decrypt(msg, nil, 0)
	if err != nil {
		panic(err)
	}
	fmt.Println("decoded")
	fmt.Println(decrypted.GetString())

	testSignMessage()
}

func testSignMessage() {
	ecKey, err := crypto.GenerateKey("mark", "steve@steve.com", "x25519", 0)
	pubKeyArmoured, err := ecKey.GetArmoredPublicKey()
	privKeyArmoured, err := ecKey.Armor()

	fmt.Println(pubKeyArmoured)
	if err != nil {
		panic(err)
	}
	publicKeyObj, err := crypto.NewKeyFromArmored(pubKeyArmoured)
	pubKeyRing, err := crypto.NewKeyRing(publicKeyObj)
	privateKeyObj, err := crypto.NewKeyFromArmored(privKeyArmoured)
	privateKeyRing, err := crypto.NewKeyRing(privateKeyObj)

	var messageEnc = crypto.NewPlainMessageFromString("some text")
	var messageDec = crypto.NewPlainMessageFromString("some text")
	pgpSig, err := privateKeyRing.SignDetached(messageEnc)
	fmt.Println(pgpSig.GetArmored())
	err = pubKeyRing.VerifyDetached(messageDec, pgpSig, crypto.GetUnixTime())

	if err != nil {
		panic(err)
	} else {
		fmt.Println("message validated successfully")
	}
}
