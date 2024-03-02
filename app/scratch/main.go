package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// Tx is the transactional information between two parties.
type Tx struct {
	FromID string `json:"from"`  // Ethereum: Account sending the transaction. Will be checked against signature.
	ToID   string `json:"to"`    // Ethereum: Account receiving the benefit of the transaction.
	Value  uint64 `json:"value"` // Ethereum: Monetary value received from this transaction.

}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {

	tx := Tx{
		FromID: "0xF01813E4B85e178A83e29B8E7bF26BD830a25f32",
		ToID:   "Aaron",
		Value:  1000,
	}

	privateKey, err := crypto.LoadECDSA("zblock/accounts/kennedy.ecdsa")
	if err != nil {
		return fmt.Errorf("unable to load private key for node: %w", err)
	}

	data, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("unable to marshal: %w", err)
	}

	v := crypto.Keccak256(data)

	sig, err := crypto.Sign(v, privateKey)
	if err != nil {
		return fmt.Errorf("unable to sign: %w", err)
	}

	fmt.Println("SIG:", hexutil.Encode(sig))

	// =========================================================================
	// OVER THE WIRE

	publicKey, err := crypto.SigToPub(v, sig)
	if err != nil {
		return fmt.Errorf("unable to pub: %w", err)
	}

	fmt.Println("PUB", crypto.PubkeyToAddress(*publicKey).String())

	// ==========================================================================

	tx2 := Tx{
		FromID: "0xF01813E4B85e178A83e29B8E7bF26BD830a25f32",
		ToID:   "Frank",
		Value:  250,
	}

	data2, err := json.Marshal(tx2)
	if err != nil {
		return fmt.Errorf("unable to marshal: %w", err)
	}

	v2 := crypto.Keccak256(data2)

	sig2, err := crypto.Sign(v2, privateKey)
	if err != nil {
		return fmt.Errorf("unable to sign: %w", err)
	}

	fmt.Println("SIG:", hexutil.Encode(sig2))

	// =========================================================================
	// OVER THE WIRE

	publicKey2, err := crypto.SigToPub(v2, sig2)
	if err != nil {
		return fmt.Errorf("unable to pub: %w", err)
	}

	// even though the signature is different, it generates the same public key
	fmt.Println("PUB", crypto.PubkeyToAddress(*publicKey2).String())

	// generally we will send the transaction and signature over the wire
	// =========================================================================
	// OVER THE WIRE
	// so here we know where the id is coming from
	// so public key is nothing but the fromID as we discussed
	tx3 := Tx{
		FromID: "0xF01813E4B85e178A83e29B8E7bF26BD830a25f32",
		ToID:   "Frank",
		Value:  250,
	}

	data3, err := json.Marshal(tx3)
	if err != nil {
		return fmt.Errorf("unable to marshal: %w", err)
	}

	v3 := crypto.Keccak256(data3)

	publicKey3, err := crypto.SigToPub(v3, sig2)
	if err != nil {
		return fmt.Errorf("unable to pub: %w", err)
	}

	fmt.Println("PUB", crypto.PubkeyToAddress(*publicKey3).String())
	return nil
}
