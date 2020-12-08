package main

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_TestNet(t *testing.T,){
	expectedPrivateKey 				:="C037EC729585778CB08B825335DA69DB5569FA35E637BDAC517E04913CFBDACE"
	//expectedBTC 					:="mvm3YfXKk6MqCmuLakkMNY4XuzuMtfXZJM"
	expectedBTC_Compressed			:="muwxb2YFzKTSSf1KZ6SC3DdEhBPLq3u1ij"
	//expectedPublicKey				:="04F67329B01296D327883CE20D354E634B96C4A597B40E95B7852612ADFF9461770237C205F7883BB0B84E7B59051AA7787B66C6308C95969D5125913DE92A24FD"
	//expectedPublicKey_Compressed 	:="03F67329B01296D327883CE20D354E634B96C4A597B40E95B7852612ADFF946177"
	expectedWIF						:="933a8EfDJfescwYXSbqvkvWF1SnLcQ9fcChrcSy1ii8SufbEzwj"
	expectedWIF_Compressed			:="cU2MCwHfJycARdk9MznxGsA4pxo7ZFBFQNfKyTcEB6XsM7U1nJnU"
	expectedSegwit					:="2N4LyCq2xZnEfP5qm7GgvsqSosUMBBTq1GS"
	expectedBech32					:="tb1qnexx0qr6mqvxl3tm9w2zytlhxax28s3ywsqy7h"
	Generate_Address(t,expectedPrivateKey,expectedBTC_Compressed,expectedWIF,expectedWIF_Compressed,expectedSegwit, expectedBech32 , &chaincfg.TestNet3Params )
}



func Test_Mainnet(t *testing.T,){
	expectedPrivateKey 				:="C037EC729585778CB08B825335DA69DB5569FA35E637BDAC517E04913CFBDACE"
	//expectedBTC 					:="1GF6FcSLw4vaRfRisBmyYcrD41Jf3ATVcV"
	expectedBTC_Compressed			:="1FS1HyTHBJ2BfYXhqXTpDJQuqBndwv6GXh"
	//expectedPublicKey				:="04F67329B01296D327883CE20D354E634B96C4A597B40E95B7852612ADFF9461770237C205F7883BB0B84E7B59051AA7787B66C6308C95969D5125913DE92A24FD"
	//expectedPublicKey_Compressed 	:="03F67329B01296D327883CE20D354E634B96C4A597B40E95B7852612ADFF946177"
	expectedWIF						:="5KGwYVqfiSajet3EpFx1tKxHMnRdTEcUGFquXpcWNyPQ8cz6wTa"
	expectedWIF_Compressed			:="L3fMk2HosuuuGCGsyaypuYf1CjVhto5ZLLWrs39ifyss6NJrw62e"
	expectedSegwit					:="3Cnm966vxKjKBJDDS954FtTYf891NXj6kf"
	expectedBech32					:="bc1qnexx0qr6mqvxl3tm9w2zytlhxax28s3yykmh9y"
	Generate_Address(t,expectedPrivateKey,expectedBTC_Compressed,expectedWIF,expectedWIF_Compressed,expectedSegwit, expectedBech32, &chaincfg.MainNetParams )
}



func Generate_Address(t *testing.T,expectedPrivateKey, expectedBTC_Compressed, expectedWIF,expectedWIF_Compressed,expectedSegwit, expectedBech32 string,chain *chaincfg.Params, ){

	privKeyBytes,_ := hex.DecodeString(expectedPrivateKey)
	privKey, pubKey := btcec.PrivKeyFromBytes(btcec.S256(),privKeyBytes)

	//Check WIF
	btcwifCompress, _ := btcutil.NewWIF(privKey,chain, true)
	wifCompressed :=btcwifCompress.String()
	assert.Equal(t,expectedWIF_Compressed,wifCompressed,"Incorrect WIF")

	btcwifUncompressed, _ := btcutil.NewWIF(privKey,chain, false)
	wifUncompressed :=btcwifUncompressed.String()
	assert.Equal(t,expectedWIF,wifUncompressed,"Incorrect WIF")

	//Check p2pkh - (Standard BTC Address)
	serializedPubKey := btcwifCompress.SerializePubKey()
	addressPubKey, _ := btcutil.NewAddressPubKey(serializedPubKey, chain)
	p2pkhAddress := addressPubKey.EncodeAddress()
	assert.Equal(t,expectedBTC_Compressed,p2pkhAddress,"Invalid p2pkh")

	//Check p2wkh - (Segwit bech32)
	witnessProg := btcutil.Hash160(serializedPubKey)
	addressWitnessPubKeyHash, _ := btcutil.NewAddressWitnessPubKeyHash(witnessProg,chain)
	segwitBech32 := addressWitnessPubKeyHash.EncodeAddress()
	assert.Equal(t,expectedBech32,segwitBech32,"Invalid p2wkh")

	//Check Segwit Nested - backwards compatible Segwit Address
	serializedScript, _ := txscript.PayToAddrScript(addressWitnessPubKeyHash)
	addressScriptHash, _ := btcutil.NewAddressScriptHash(serializedScript, chain)
	segwitNested := addressScriptHash.EncodeAddress()
	assert.Equal(t,expectedSegwit,segwitNested,"Invalid segwit address")

	//Check NestedWitnessPubKey - "BIP049 nested P2WKH", this is what btcsuite uses

	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	witAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash,chain)
	assert.Nil(t, err ,"Error is nil")
	witnessProgram, err := txscript.PayToAddrScript(witAddr)
	address, err := btcutil.NewAddressScriptHash(witnessProgram,chain)
	assert.Equal(t,expectedSegwit,address.EncodeAddress(),"Invalid segwit address")
	assert.Equal(t, segwitNested,address.EncodeAddress(),"Segwit calculations different")


}
