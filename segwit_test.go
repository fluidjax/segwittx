package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/stretchr/testify/assert"
	"testing"
)

//Generate  Segwit Testnet Transactions

func Test_Segwit(t *testing.T) {
	var err error
	//Sending back to self
	err = CreateTransaction("933a8EfDJfescwYXSbqvkvWF1SnLcQ9fcChrcSy1ii8SufbEzwj", "2N4LyCq2xZnEfP5qm7GgvsqSosUMBBTq1GS", 1000, 10000, "a91479bf89e019333a0a7caf926c2c69a656f4a0c67587","bab0a129f1c3ad504971aa8cb99628ba71d85b160cd731e84d55320caa5d1f56", &chaincfg.TestNet3Params, "932a9d2911792259f952fe09868f38eb687f30b69c6163c54e9b5c34a214b7ec")
	assert.Nil(t, err, "Error", err)

	//Sending to P2PKH
	err = CreateTransaction("933a8EfDJfescwYXSbqvkvWF1SnLcQ9fcChrcSy1ii8SufbEzwj", "mjTabrhCExmGzAP3sYH43AVWJfCYf5D9WZ", 1000, 10000, "a91479bf89e019333a0a7caf926c2c69a656f4a0c67587","552d746721d7c398b268871e2add683ec89c46bc8e75cfeeccc4d352e618fcef", &chaincfg.TestNet3Params, "46efa28e9ba27e89514de5a5ae8b7072955bbe9e240906d4727f333d5b4ba152")
	assert.Nil(t, err, "Error", err)
}


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

func CreateTransaction(secret string, destination string, sendAmount int64, utxoAmount int64, utxoScript string,  txHash string, chain *chaincfg.Params, expectedTransactionHash string) error {
	wif, _ := btcutil.DecodeWIF(secret)

	//Outgoing TX Address
	addr, _ := btcutil.DecodeAddress(destination, chain)
	p2shAddr, _ := txscript.PayToAddrScript(addr)
	utxOut := wire.NewTxOut(sendAmount, p2shAddr)

	//Input scripts array (for validation checks)
	inscript1, _ := hex.DecodeString(utxoScript)
	var inputUtxoScripts [][]byte
	inputUtxoScripts = append(inputUtxoScripts, inscript1)


	//Incoming UTXO
	incomingTXHash, _ := chainhash.NewHashFromStr(txHash)
	prevOut := wire.OutPoint{
		Hash:  *incomingTXHash,
		Index: 0,
	}

	outgoingTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: prevOut,
		}},
		TxOut: []*wire.TxOut{utxOut},
	}

	sigHashes := txscript.NewTxSigHashes(outgoingTx)

	witness, script, _ := ComputeInputScript(wif, outgoingTx, utxoAmount, 0, sigHashes, txscript.SigHashAll, chain)
	outgoingTx.TxIn[0].Witness = witness
	outgoingTx.TxIn[0].SignatureScript = script



	//Dump final Hex transaction
	buf := new(bytes.Buffer)
	_ = outgoingTx.Serialize(buf)
	fmt.Println(hex.EncodeToString(buf.Bytes()))

	//If an expected result is passed, check it
	entireTXHash := sha256.Sum256(buf.Bytes())
	entireTXHashHex := hex.EncodeToString(entireTXHash[:])

	if expectedTransactionHash != "" && entireTXHashHex != expectedTransactionHash {
		return errors.New("Expected Transaction doesn't match generated transaction: "+entireTXHashHex)
	}


	//Validate the Result
	utxo1amount := btcutil.Amount(utxoAmount)
	validateError := validateMsgTx(outgoingTx, inputUtxoScripts, []btcutil.Amount{utxo1amount})
	if validateError != nil {
		return validateError
	}

	return nil
}

func validateMsgTx(tx *wire.MsgTx, prevScripts [][]byte, inputValues []btcutil.Amount) error {
	hashCache := txscript.NewTxSigHashes(tx)
	for i, prevScript := range prevScripts {
		vm, err := txscript.NewEngine(prevScript, tx, i,txscript.StandardVerifyFlags, nil, hashCache, int64(inputValues[i]))
		if err != nil {
			return fmt.Errorf("cannot create script engine: %s", err)
		}
		err = vm.Execute()
		if err != nil {
			return fmt.Errorf("cannot validate transaction: %s", err)
		}
	}
	return nil
}

func ComputeInputScript(wif *btcutil.WIF, tx *wire.MsgTx, inputUTXOAmount int64, inputIndex int, sigHashes *txscript.TxSigHashes, hashType txscript.SigHashType, chain *chaincfg.Params) (wire.TxWitness,
	[]byte, error) {

	wif.CompressPubKey = true
	pubKey := wif.SerializePubKey()
	privKey := wif.PrivKey

	var (
		witnessProgram []byte
		sigScript      []byte
	)
	pubKeyHash := btcutil.Hash160(pubKey)
	//fmt.Println("pubKeyHash ",hex.EncodeToString(pubKeyHash))

	// Next, we'll generate a valid sigScript that will allow us to
	// spend the p2sh output. The sigScript will contain only a
	// single push of the p2wkh witness program corresponding to
	// the matching public key of this address.
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, chain)
	if err != nil {
		return nil, nil, err
	}
	witnessProgram, err = txscript.PayToAddrScript(p2wkhAddr)
	//fmt.Println("witnessProgram ",hex.EncodeToString(witnessProgram))

	if err != nil {
		return nil, nil, err
	}

	bldr := txscript.NewScriptBuilder()
	bldr.AddData(witnessProgram)
	sigScript, err = bldr.Script()
	if err != nil {
		return nil, nil, err
	}

	// Otherwise, this is a regular p2wkh output, so we include the
	// witness program itself as the subscript to generate the proper
	// sighash digest. As part of the new sighash digest algorithm, the
	// p2wkh witness program will be expanded into a regular p2kh
	// script.

	// Generate a valid witness stack for the input.
	witnessScript, err := txscript.WitnessSignature(
		tx, sigHashes, inputIndex, inputUTXOAmount, witnessProgram,
		hashType, privKey, true,
	)
	if err != nil {
		return nil, nil, err
	}

	return witnessScript, sigScript, nil
}
