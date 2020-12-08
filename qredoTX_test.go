package main

//Internal Qredo requirements fullfillment & testing
//This is probably not much use to anyone else, Im just identifying which fields we have/need for a specific implementation


/* Requirements:


type SettleInput struct {
	Address           string                   // From address in string format
	UnderlyingPayload protobuffer.PBUnderlying // Underlying transaction payload
	Change            int64                    // For Bitcoin this represents wehether the underlying input is change. Ethereum it is unused (0)
	State             SetttlInputState         // For Bitcoin this is spent or unspent
	Nonce             uint64                   // (v1.2 or later) For Ethereum inputs this value must be tracked and increase by one each time the address is used. For Bitcoin this field is unused (0).
	CurrentBalance    int64                    // Current Balance of the account input
}

type SettleOutput struct {
	Address   string
	Type      int
	Amount    int64
	PublicKey string
	SeedID    []byte
	Payload   []byte // Needed for smart contract transactions (v1.5 or later)
}



	UnderlyingForSigning(
		inputs []*SettleInput,
		extraInputs []*SettleInput,
		FeeUnit int64,
		outputs []*SettleOutput,
		qredoFeePerc float64,
		minerFeeChargable int64,
		currency protobuffer.PBCryptoCurrency,
		deliver bool,
		amount int64,
		fee int64)
	(*protobuffer.PBSettlementTransaction, ichangeAmount, totalFeeToQredo, actualSettlementAmount, []*SettleInput, reuseMarker, error)


//func CreateTransaction(secret string, destination string, sendAmount int64, utxoAmount int64, utxoScript string,  txHash string, chain *chaincfg.Params, expectedTransactionHash string) error {

1) Update watcher to issue segwit addresses
2) Create snapshot chain, with wallets with segwit addresses
3) Ammend underlying/bitcoin/settletransaction.go to build correct unsigned TX
4) Note txscript.CalcWitnessSigHash(script []byte, sigHashes *TxSigHashes, hType SigHashType,tx *wire.MsgTx, idx int, amt int64) ([]byte, error)

Watcher
Sign the hashes and build the witness & script


 */