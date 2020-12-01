

package main

import (
	"bytes"
	"encoding/hex"


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

func CreateTransaction(secret string, destination string, amount int64, txHash string) (error) {

	wif, err := btcutil.DecodeWIF(secret)
	addresspubkey, _ := btcutil.NewAddressPubKey(wif.PrivKey.PubKey().SerializeUncompressed(), &chaincfg.MainNetParams)


	sourceTx := wire.NewMsgTx(wire.TxVersion)
	sourceUtxoHash, _ := chainhash.NewHashFromStr(txHash)
	sourceUtxo := wire.NewOutPoint(sourceUtxoHash, 0)
	sourceTxIn := wire.NewTxIn(sourceUtxo, nil, nil)
	destinationAddress, err := btcutil.DecodeAddress(destination, &chaincfg.MainNetParams)

	sourceAddress, err := btcutil.DecodeAddress(addresspubkey.EncodeAddress(), &chaincfg.MainNetParams)
	if err != nil {
		return  err
	}
	destinationPkScript, _ := txscript.PayToAddrScript(destinationAddress)
	sourcePkScript, _ := txscript.PayToAddrScript(sourceAddress)



	sourceTxOut := wire.NewTxOut(amount, sourcePkScript)
	sourceTx.AddTxIn(sourceTxIn)
	sourceTx.AddTxOut(sourceTxOut)
	sourceTxHash := sourceTx.TxHash()
	redeemTx := wire.NewMsgTx(wire.TxVersion)
	prevOut := wire.NewOutPoint(&sourceTxHash, 0)
	redeemTxIn := wire.NewTxIn(prevOut, nil, nil)
	redeemTx.AddTxIn(redeemTxIn)
	redeemTxOut := wire.NewTxOut(amount, destinationPkScript)
	redeemTx.AddTxOut(redeemTxOut)

	sigHashes := txscript.NewTxSigHashes(redeemTx)

	witness, script, err := ComputeInputScript(wif, redeemTx, sourceTxOut, 0, sigHashes, txscript.SigHashAll)
	redeemTx.TxIn[0].Witness = witness
	redeemTx.TxIn[0].SignatureScript = script


	///////////////////
	buf := new(bytes.Buffer)
	err = redeemTx.Serialize(buf)
	print(hex.EncodeToString(buf.Bytes()))




	return  nil
}


func ComputeInputScript(wif *btcutil.WIF, tx *wire.MsgTx, output *wire.TxOut,	inputIndex int, sigHashes *txscript.TxSigHashes,hashType txscript.SigHashType) (wire.TxWitness,
	[]byte, error) {

	pubKey := wif.SerializePubKey()
	privKey := wif.PrivKey

	var (
		witnessProgram []byte
		sigScript      []byte
	)
	pubKeyHash := btcutil.Hash160(pubKey)

	// Next, we'll generate a valid sigScript that will allow us to
	// spend the p2sh output. The sigScript will contain only a
	// single push of the p2wkh witness program corresponding to
	// the matching public key of this address.
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		pubKeyHash,&chaincfg.TestNet3Params ,
	)
	if err != nil {
		return nil, nil, err
	}
	witnessProgram, err = txscript.PayToAddrScript(p2wkhAddr)
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
		tx, sigHashes, inputIndex, output.Value, witnessProgram,
		hashType, privKey, true,
	)
	if err != nil {
		return nil, nil, err
	}

	return witnessScript, sigScript, nil
}



func main() {
	_ = CreateTransaction("5KPhot5fJ3x1TaPpCJGn6UPZRP7MqKEExDed5R39AzPFquQZ4zW", "35XLRj4WPu7FifEWzMsRvWvn9bNng9vhd5", 1000, "73c9fec091af7d5fa74650e758b40b4f9895404d1cb95193b6ec059a541dd44f")




}
