

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

type Transaction struct {
	TxId               string `json:"txid"`
	SourceAddress      string `json:"source_address"`
	DestinationAddress string `json:"destination_address"`
	Amount             int64  `json:"amount"`
	UnsignedTx         string `json:"unsignedtx"`
	SignedTx           string `json:"signedtx"`
}

func main() {

	//CreateTransaction("93KWUgeZET9vTXLoiVmDNJePrVJVmht2UhUtNK78WKHYbf5YaRc", "mzfrHhpyqVdBYPUtoRtuuoBT9bh9cFG388", 1000, "9ad8beecf52bf55580a359684ff506346b00bc06583336dc0f618af4574ab9bd",&chaincfg.TestNet3Params)
	//CreateTransaction("92M2DhFHasE9S66UEFmcvYAKRdHnEn7DmD3cFj1Dk7SSiTGV3Ys", "tb1qs6afttm4wkvfueef8djrphmnkcpyjhqjfa6skw", 1000, "c8dafd427a9744bcd97fe4a3d045c9d49679b0d9d27141e76d4e198f929bffda",&chaincfg.TestNet3Params)


	CreateTransaction("933a8EfDJfescwYXSbqvkvWF1SnLcQ9fcChrcSy1ii8SufbEzwj", "2N4LyCq2xZnEfP5qm7GgvsqSosUMBBTq1GS", 1000, "6615134f20390fbb8bec4b0373988efa1f8ef9f56de6c495a37b8188ee2c6fec",&chaincfg.TestNet3Params)


}

func CreateTransaction(secret string, destination string, amount int64, txHash string, chain *chaincfg.Params ) (error) {
	wif, _ := btcutil.DecodeWIF(secret)
	addr, _ := btcutil.DecodeAddress(destination, chain)
	fmt.Println("string addr", addr.String())
	p2shAddr, _ := txscript.PayToAddrScript(addr)
	fmt.Println("string p2shAddr", hex.EncodeToString(p2shAddr))
	utxOut := wire.NewTxOut(amount, p2shAddr)

	incomingTXHash, _ := chainhash.NewHashFromStr(txHash)
	prevOut := wire.OutPoint{
		Hash:  *incomingTXHash,
		Index: 0,
	}

	fmt.Println("incomingTx.TxHash()",incomingTXHash)

	outgoingTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: prevOut,
		}},
		TxOut: []*wire.TxOut{utxOut},
	}

	sigHashes := txscript.NewTxSigHashes(outgoingTx)

	witness, script, _ := ComputeInputScript(wif, outgoingTx, utxOut, 0,sigHashes, txscript.SigHashAll, chain)

	for a,_ := range witness {
		fmt.Println("Witness ",a,hex.EncodeToString(witness[a]))
	}
	fmt.Println("script", hex.EncodeToString(script))

	outgoingTx.TxIn[0].Witness = witness
	outgoingTx.TxIn[0].SignatureScript = script
	///////////////////

	err := validateMsgTx(outgoingTx, [][]byte{utxOut.PkScript}, []btcutil.Amount{1000},)
	if err != nil {
		fmt.Println(err)
	}

	buf := new(bytes.Buffer)
	_ = outgoingTx.Serialize(buf)
	print(hex.EncodeToString(buf.Bytes()))
	return  nil
}


func validateMsgTx(tx *wire.MsgTx, prevScripts [][]byte, inputValues []btcutil.Amount) error {
	hashCache := txscript.NewTxSigHashes(tx)
	for i, prevScript := range prevScripts {
		vm, err := txscript.NewEngine(prevScript, tx, i,
			txscript.StandardVerifyFlags, nil, hashCache, int64(inputValues[i]))
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


func ComputeInputScript(wif *btcutil.WIF, tx *wire.MsgTx, output *wire.TxOut,	inputIndex int, sigHashes *txscript.TxSigHashes,hashType txscript.SigHashType,chain *chaincfg.Params) (wire.TxWitness,
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
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash,chain ,)
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
		tx, sigHashes, inputIndex, 10000, witnessProgram,
		hashType, privKey, true,
	)
	if err != nil {
		return nil, nil, err
	}

	return witnessScript, sigScript, nil
}


//func Segwit(secret string, destination string, amount int64, txHash string)  {
//	chain :=  &chaincfg.TestNet3Params
//	wif, _ := btcutil.DecodeWIF(secret)
//
//
//
//	redeemTx := wire.NewMsgTx(wire.TxVersion)
//	sourceTxHash, _ := chainhash.NewHashFromStr(txHash)
//	prevOut := wire.NewOutPoint(sourceTxHash, 0)
//	redeemTxIn := wire.NewTxIn(prevOut, nil, nil)
//	redeemTx.AddTxIn(redeemTxIn)
//
//	destinationAddress, _ := btcutil.DecodeAddress(destination, chain)
//	destinationPkScript, _ := txscript.PayToAddrScript(destinationAddress)
//	redeemTxOut := wire.NewTxOut(amount, destinationPkScript)
//	redeemTx.AddTxOut(redeemTxOut)
//	//inputScript,_ := hex.DecodeString("a91422d90622f1a8cda9260f5e287a880eb3b9f52eb287")
//	sigHashes := txscript.NewTxSigHashes(redeemTx)
//
//	witness, script, _ := ComputeInputScript2(wif, redeemTx, int64(100), 0, sigHashes, txscript.SigHashAll,chain)
//	redeemTx.TxIn[0].Witness = witness
//	redeemTx.TxIn[0].SignatureScript = script
//
//
//	var signedTx bytes.Buffer
//	redeemTx.Serialize(&signedTx)
//	fmt.Println(hex.EncodeToString(signedTx.Bytes()))
//}

//
//func OriginalCreateTransaction(secret string, destination string, amount int64, txHash string)  {
//	//chain :=  &chaincfg.MainNetParams
//	chain :=  &chaincfg.TestNet3Params
//
//	//var transaction Transaction
//	wif, err := btcutil.DecodeWIF(secret)
//	//if err != nil {
//	//	return Transaction{}, err
//	//}
//	//addresspubkey, _ := btcutil.NewAddressPubKey(wif.PrivKey.PubKey().SerializeUncompressed(), chain)
//	//sourceTx := wire.NewMsgTx(wire.TxVersion)
//	//sourceUtxoHash, _ := chainhash.NewHashFromStr(txHash)
//	//sourceUtxo := wire.NewOutPoint(sourceUtxoHash, 0)
//	//sourceTxIn := wire.NewTxIn(sourceUtxo, nil, nil)
//
//	//sourceAddress, err := btcutil.DecodeAddress(addresspubkey.EncodeAddress(),chain)
//	//if err != nil {
//	//	return Transaction{}, err
//	//}
//
//	//sourcePkScript, _ := txscript.PayToAddrScript(sourceAddress)
//	//sourceTxOut := wire.NewTxOut(amount, sourcePkScript)
//	//sourceTx.AddTxIn(sourceTxIn)
//	//sourceTx.AddTxOut(sourceTxOut)
//	//sourceTxHash := sourceTx.TxHash()
//
//	redeemTx := wire.NewMsgTx(wire.TxVersion)
//
//	sourceTxHash, _ := chainhash.NewHashFromStr(txHash)
//	prevOut := wire.NewOutPoint(sourceTxHash, 0)
//	redeemTxIn := wire.NewTxIn(prevOut, nil, nil)
//	redeemTx.AddTxIn(redeemTxIn)
//
//	destinationAddress, err := btcutil.DecodeAddress(destination, chain)
//	destinationPkScript, _ := txscript.PayToAddrScript(destinationAddress)
//	redeemTxOut := wire.NewTxOut(amount, destinationPkScript)
//	redeemTx.AddTxOut(redeemTxOut)
//
//	inputScript,_ := hex.DecodeString("76a914ee37c1c620fdee0bcab60148719ed839b122b2d388ac")
//
//	sigScript, err := txscript.SignatureScript(redeemTx, 0, inputScript, txscript.SigHashAll, wif.PrivKey, false)
//	if err != nil {
//		return
//	}
//	redeemTx.TxIn[0].SignatureScript = sigScript
//	flags := txscript.StandardVerifyFlags
//	vm, err := txscript.NewEngine(inputScript, redeemTx, 0, flags, nil, nil, amount)
//	if err != nil {
//		return
//	}
//	if err := vm.Execute(); err != nil {
//		return
//	}
//	var signedTx bytes.Buffer
//	redeemTx.Serialize(&signedTx)
//	fmt.Println(hex.EncodeToString(signedTx.Bytes()))
//}
