package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

// Test_Segwit_External_Signing the hash & sign parts of the segwit transaction are buried inside the btsuite and are perforemed during
// txscript.WitnessSignature - the following test splits these operations into
// 1) Returns the hashes which will be used by the Qredoserver and put into the PBSettlementTransaction  / PBSettlementTransactionInput
// 2) These hashes are then signed by the MPCs in a separate process.

//Multi-input transactions
//Mixed input transactions
//Isolate required fields




func Test_Segwit_External_Signing(t *testing.T) {
	fmt.Println("EXTERNAL")
		var err error
	////Sending back to self
	//err = CreateTransaction2("933a8EfDJfescwYXSbqvkvWF1SnLcQ9fcChrcSy1ii8SufbEzwj", "2N4LyCq2xZnEfP5qm7GgvsqSosUMBBTq1GS", 1000, 10000, "a91479bf89e019333a0a7caf926c2c69a656f4a0c67587","bab0a129f1c3ad504971aa8cb99628ba71d85b160cd731e84d55320caa5d1f56", &chaincfg.TestNet3Params, "932a9d2911792259f952fe09868f38eb687f30b69c6163c54e9b5c34a214b7ec")
	////00000000000101561f5daa0c32554de831d70c165bd871ba2896b98caa714950adc3f129a1b0ba00000000171600149e4c67807ad8186fc57b2b94222ff7374ca3c2240000000001e80300000000000017a91479bf89e019333a0a7caf926c2c69a656f4a0c6758702483045022100f8aba5154b81672d12483b4a08bbb25f25d03a98fd218f35b3ebc524c4905bbe02202d5923a847bd6987353d520776c7e51df077eee235bb13604f03332fd44c64b3012103f67329b01296d327883ce20d354e634b96c4a597b40e95b7852612adff94617700000000
	//assert.Nil(t, err, "Error", err)
	//
	////Sending to P2PKH
	//err = CreateTransaction2("933a8EfDJfescwYXSbqvkvWF1SnLcQ9fcChrcSy1ii8SufbEzwj", "mjTabrhCExmGzAP3sYH43AVWJfCYf5D9WZ", 1000, 10000, "a91479bf89e019333a0a7caf926c2c69a656f4a0c67587","552d746721d7c398b268871e2add683ec89c46bc8e75cfeeccc4d352e618fcef", &chaincfg.TestNet3Params, "46efa28e9ba27e89514de5a5ae8b7072955bbe9e240906d4727f333d5b4ba152")
	////00000000000101effc18e652d3c4cceecf758ebc469cc83e68dd2a1e8768b298c3d72167742d5500000000171600149e4c67807ad8186fc57b2b94222ff7374ca3c2240000000001e8030000000000001976a9142b3d25955c7eb723e68c68d363aad8db9440a00f88ac0247304402207da23b87cec073dfe31dbbb85ffc6352d7089b17d595c32bee01d949646cb25502203d5a570cd92facb02d0541438b7c91ee2608f5026f00a62d7f9be234dc0fc2e1012103f67329b01296d327883ce20d354e634b96c4a597b40e95b7852612adff94617700000000
	//assert.Nil(t, err, "Error", err)
	//
	//

	//Setup

	//UTXO
	utxoScript :="a91479bf89e019333a0a7caf926c2c69a656f4a0c67587"
	txHash := "552d746721d7c398b268871e2add683ec89c46bc8e75cfeeccc4d352e618fcef"
	pubkey := "03F67329B01296D327883CE20D354E634B96C4A597B40E95B7852612ADFF946177"
	utxoAmount := int64(10000)
	index := 0

	chain := &chaincfg.TestNet3Params
	amountToSend := int64(1000)
	destinationAddress := "mjTabrhCExmGzAP3sYH43AVWJfCYf5D9WZ"


	//Qredochain

	//make  UnsignedTX
	unsignedTX, err := UnsignedBuildTX(destinationAddress, amountToSend, utxoScript ,txHash, chain)
	assert.Nil(t, err, "Error", err)
	bufUnsigned := new(bytes.Buffer)
	_ = unsignedTX.Serialize(bufUnsigned)
	entireTXHashUnsigned := sha256.Sum256(bufUnsigned.Bytes())
	entireTXHashHexUnsigned := hex.EncodeToString(entireTXHashUnsigned[:])
	assert.Equal(t, "e2f1e55ab2e2573d3d467766d00588ce99dce6d57d5ae5e4a22f9c1d42fab6aa",entireTXHashHexUnsigned,"Invalid unsigned TX")

	//Make Hashes
	pubKeyBytes, _ := hex.DecodeString(pubkey)
	hashType := txscript.SigHashAll
    hash, err := HashBuild(unsignedTX, index, utxoAmount, hashType, pubKeyBytes, chain)
	assert.Nil(t, err, "Error", err)




	//Watcher

	//Sign Hash
	//make wif for signing only
	compress := true
	wif, _ := btcutil.DecodeWIF("933a8EfDJfescwYXSbqvkvWF1SnLcQ9fcChrcSy1ii8SufbEzwj")
	privKey := wif.PrivKey
	signature, err := privKey.Sign(hash)
	sig := append(signature.Serialize(), byte(hashType))
	pk, err := btcec.ParsePubKey(pubKeyBytes,btcec.S256())
	assert.Nil(t, err, "Error", err)
	var pkData []byte
	if compress {
		pkData = pk.SerializeCompressed()
	} else {
		pkData = pk.SerializeUncompressed()
	}
	witness := wire.TxWitness{sig, pkData}



	//finalize Transaction
	//make sigScript  - (again )
	pubKeyHash := btcutil.Hash160(pubKeyBytes)
	fmt.Println("pubKeyHash ",hex.EncodeToString(pubKeyHash))
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, chain)
	assert.Nil(t, err, "Error", err)
	witnessProgram, err := txscript.PayToAddrScript(p2wkhAddr)

	assert.Equal(t,"00149e4c67807ad8186fc57b2b94222ff7374ca3c224",hex.EncodeToString(witnessProgram),"Invalid witness program")

	bldr := txscript.NewScriptBuilder()
	bldr.AddData(witnessProgram)
	sigScript, err := bldr.Script()

	unsignedTX.TxIn[0].Witness = witness
	unsignedTX.TxIn[0].SignatureScript = sigScript


	//final check
	//If an expected result is passed, check it
	buf := new(bytes.Buffer)
	_ = unsignedTX.Serialize(buf)
	entireTXHash := sha256.Sum256(buf.Bytes())
	entireTXHashHex := hex.EncodeToString(entireTXHash[:])

	assert.Equal(t, "46efa28e9ba27e89514de5a5ae8b7072955bbe9e240906d4727f333d5b4ba152",entireTXHashHex,"Invalid final TX")


}

func HashBuild(unsignedTX *wire.MsgTx, inputIndex int ,sendAmount int64,  hashType  txscript.SigHashType, pubKey []byte,chain *chaincfg.Params) ([]byte , error) {
	sigHashes := txscript.NewTxSigHashes(unsignedTX)


	pubKeyHash := btcutil.Hash160(pubKey)
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, chain)
	if err != nil {
		return  nil, err
	}
	witnessProgram, err := txscript.PayToAddrScript(p2wkhAddr)
	fmt.Println("WitnessProgram "+ hex.EncodeToString(witnessProgram))

	//parsedScript, err := parseScript(subScript)
	hash, err := txscript.CalcWitnessSigHash(witnessProgram, sigHashes, hashType, unsignedTX,inputIndex, sendAmount)
	fmt.Println("HASH:"+hex.EncodeToString(hash))
	return hash, nil
}


func UnsignedBuildTX(destination string, sendAmount int64, utxoScript string,  txHash string, chain *chaincfg.Params) (*wire.MsgTx, error) {
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

	//sigHashes := txscript.NewTxSigHashes(outgoingTx)
	return outgoingTx,nil


}




func validateMsgTx2(tx *wire.MsgTx, prevScripts [][]byte, inputValues []btcutil.Amount) error {
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


func WitnessSignature(tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, idx int, amt int64,
	subscript []byte, hashType txscript.SigHashType, privKey *btcec.PrivateKey,
	compress bool) (wire.TxWitness, error) {

	sig, err := RawTxInWitnessSignature(tx, sigHashes, idx, amt, subscript,	hashType, privKey)
	if err != nil {
		return nil, err
	}

	pk := (*btcec.PublicKey)(&privKey.PublicKey)
	var pkData []byte
	if compress {
		pkData = pk.SerializeCompressed()
	} else {
		pkData = pk.SerializeUncompressed()
	}

	// A witness script is actually a stack, so we return an array of byte
	// slices here, rather than a single byte slice.
	return wire.TxWitness{sig, pkData}, nil
}

func RawTxInWitnessSignature(tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, idx int,
	amt int64, subScript []byte, hashType txscript.SigHashType,	key *btcec.PrivateKey) ([]byte, error) {

	hash, err := txscript.CalcWitnessSigHash(subScript, sigHashes, hashType, tx, idx, amt)
	if err != nil {
		return nil, err
	}

	signature, err := key.Sign(hash)
	if err != nil {
		return nil, fmt.Errorf("cannot sign tx input: %s", err)
	}

	return append(signature.Serialize(), byte(hashType)), nil
}

