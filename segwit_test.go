package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	fmt.Println("INTERNAL")
	var err error
	//Sending back to self
	//err = CreateTransaction("933a8EfDJfescwYXSbqvkvWF1SnLcQ9fcChrcSy1ii8SufbEzwj", "2N4LyCq2xZnEfP5qm7GgvsqSosUMBBTq1GS", 1000, 10000, "a91479bf89e019333a0a7caf926c2c69a656f4a0c67587","bab0a129f1c3ad504971aa8cb99628ba71d85b160cd731e84d55320caa5d1f56", &chaincfg.TestNet3Params, "932a9d2911792259f952fe09868f38eb687f30b69c6163c54e9b5c34a214b7ec")
	////00000000000101561f5daa0c32554de831d70c165bd871ba2896b98caa714950adc3f129a1b0ba00000000171600149e4c67807ad8186fc57b2b94222ff7374ca3c2240000000001e80300000000000017a91479bf89e019333a0a7caf926c2c69a656f4a0c6758702483045022100f8aba5154b81672d12483b4a08bbb25f25d03a98fd218f35b3ebc524c4905bbe02202d5923a847bd6987353d520776c7e51df077eee235bb13604f03332fd44c64b3012103f67329b01296d327883ce20d354e634b96c4a597b40e95b7852612adff94617700000000
	//assert.Nil(t, err, "Error", err)

	//Sending to P2PKH
	err = CreateTransaction("933a8EfDJfescwYXSbqvkvWF1SnLcQ9fcChrcSy1ii8SufbEzwj", "mjTabrhCExmGzAP3sYH43AVWJfCYf5D9WZ", 1000, 10000, "a91479bf89e019333a0a7caf926c2c69a656f4a0c67587","552d746721d7c398b268871e2add683ec89c46bc8e75cfeeccc4d352e618fcef", &chaincfg.TestNet3Params, "46efa28e9ba27e89514de5a5ae8b7072955bbe9e240906d4727f333d5b4ba152")
	//00000000000101effc18e652d3c4cceecf758ebc469cc83e68dd2a1e8768b298c3d72167742d5500000000171600149e4c67807ad8186fc57b2b94222ff7374ca3c2240000000001e8030000000000001976a9142b3d25955c7eb723e68c68d363aad8db9440a00f88ac0247304402207da23b87cec073dfe31dbbb85ffc6352d7089b17d595c32bee01d949646cb25502203d5a570cd92facb02d0541438b7c91ee2608f5026f00a62d7f9be234dc0fc2e1012103f67329b01296d327883ce20d354e634b96c4a597b40e95b7852612adff94617700000000
	assert.Nil(t, err, "Error", err)
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


	bufUnsigned := new(bytes.Buffer)
	_ = outgoingTx.Serialize(bufUnsigned)
	entireTXHashUnsigned := sha256.Sum256(bufUnsigned.Bytes())
	entireTXHashHexUnsigned := hex.EncodeToString(entireTXHashUnsigned[:])
	fmt.Println("Hash of Unsigned TX ",entireTXHashHexUnsigned )





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
	fmt.Println("pubKeyHash ",hex.EncodeToString(pubKeyHash))

	// Next, we'll generate a valid sigScript that will allow us to
	// spend the p2sh output. The sigScript will contain only a
	// single push of the p2wkh witness program corresponding to
	// the matching public key of this address.
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, chain)
	if err != nil {
		return nil, nil, err
	}
	witnessProgram, err = txscript.PayToAddrScript(p2wkhAddr)
	fmt.Println("witnessProgram ",hex.EncodeToString(witnessProgram))

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
