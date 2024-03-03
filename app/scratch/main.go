package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"

	"github.com/ardanlabs/blockchain/foundation/blockchain/database"
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

	stamp := []byte(fmt.Sprintf("\x19Ardan Signed Message:\n%d", len(data)))
	v := crypto.Keccak256(stamp, data)

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

	stamp = []byte(fmt.Sprintf("\x19Ardan Signed Message:\n%d", len(data)))

	v2 := crypto.Keccak256(stamp, data2)

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

	stamp = []byte(fmt.Sprintf("\x19Ardan Signed Message:\n%d", len(data)))

	v3 := crypto.Keccak256(stamp, data3)

	publicKey3, err := crypto.SigToPub(v3, sig2)
	if err != nil {
		return fmt.Errorf("unable to pub: %w", err)
	}

	fmt.Println("PUB", crypto.PubkeyToAddress(*publicKey3).String())

	vv, r, s, err := ToVRSFromHexSignature(hexutil.Encode(sig2))
	if err != nil {
		return fmt.Errorf("unable to convert: %w", err)
	}

	fmt.Println("V|R|S", vv, r, s)

	fmt.Println("=================== TX ==========================")

	billTx, err := database.NewTx(1, 1,
		"0xF01813E4B85e178A83e29B8E7bF26BD830a25f32",
		"0xbEE6ACE826eC3DE1B6349888B9151B92522F7F76",
		1000,
		0,
		nil)

	if err != nil {
		return fmt.Errorf("unable to Billtx: %w", err)
	}

	signedTx, err := billTx.Sign(privateKey)
	if err != nil {
		return fmt.Errorf("unable to signedTx: %w", err)
	}

	fmt.Println(signedTx)

	return nil
}

// ToVRSFromHexSignature converts a hex representation of the signature into
// its R, S and V parts.
func ToVRSFromHexSignature(sigStr string) (v, r, s *big.Int, err error) {
	// you are decoding by not include tha "0x" part
	sig, err := hex.DecodeString(sigStr[2:])
	if err != nil {
		return nil, nil, nil, err
	}

	// we use SetBytes here, because the integer value that being created for r and s
	// ended up being like 31 byte value , it was smaller than 32 bytes it has leding zero
	// in byte signature, so out of big int we have a wrong number
	// what SetBytes does is that it identifies whether the number is smaller and says that
	// 32 bytes of capacity we have here and store it  properly and convert it back so we can work.

	r = big.NewInt(0).SetBytes(sig[:32])
	s = big.NewInt(0).SetBytes(sig[32:64])
	v = big.NewInt(0).SetBytes([]byte{sig[64]})

	return v, r, s, nil
}
