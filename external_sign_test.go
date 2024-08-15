package externalsign

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/morph-l2/go-ethereum/common"
	"github.com/morph-l2/go-ethereum/common/hexutil"
	"github.com/morph-l2/go-ethereum/core/types"
	"github.com/morph-l2/go-ethereum/crypto"
	"github.com/morph-l2/go-ethereum/crypto/kzg4844"
	"github.com/stretchr/testify/require"
)

func TestRequestSign(t *testing.T) {

	appid := "morph-tx-submitter-399A1722-3F2C-4E39-ABD2-1B65D02C66BA"
	rsaPrivStr := ""
	url := "http://localhost:8080/v1/sign/tx_sign"
	addr := "0x33d5b507868b7e8ac930cd3bde9eadd60c638479"
	chain := "QANET-L1"
	chainid := big.NewInt(900)
	signer := types.LatestSignerForChainID(chainid)

	rsa, err := ParseRsaPrivateKey(rsaPrivStr)
	require.NoError(t, err)
	es := NewExternalSign(appid, rsa, addr, chain, signer)

	// testdata
	topk, err := crypto.GenerateKey()
	require.NoError(t, err)
	toaddr := crypto.PubkeyToAddress(topk.PublicKey)
	gas := uint64(50000)

	txdata := &types.DynamicFeeTx{
		To:        &toaddr,
		Gas:       gas,
		GasFeeCap: big.NewInt(1),
		GasTipCap: big.NewInt(2),
		Value:     big.NewInt(3),
		ChainID:   chainid,
	}
	txdatas := make([]types.TxData, 0)
	txdatas = append(txdatas, txdata, createEmptyBlobTxInner(true))

	for _, txdata := range txdatas {

		tx := types.NewTx(txdata)
		signedTx, err := es.RequestSign(url, tx)
		require.NoError(t, err)
		from, err := signer.Sender(signedTx)
		require.NoError(t, err)
		require.Equal(t, hexutil.Encode(from.Bytes()), addr)
		switch tp := txdata.(type) {
		case *types.DynamicFeeTx:
			require.Equal(t, tp.Gas, signedTx.Gas())
			require.Equal(t, tp.GasFeeCap.Uint64(), signedTx.GasFeeCap().Uint64())
			require.Equal(t, tp.GasTipCap.Uint64(), signedTx.GasTipCap().Uint64())
			require.Equal(t, tp.Value.Uint64(), signedTx.Value().Uint64())
			require.Equal(t, tp.Data, signedTx.Data())
		case *types.BlobTx:
			require.Equal(t, tp.Gas, signedTx.Gas())
			require.Equal(t, tp.GasFeeCap.Uint64(), signedTx.GasFeeCap().Uint64())
			require.Equal(t, tp.GasTipCap.Uint64(), signedTx.GasTipCap().Uint64())
			require.Equal(t, tp.Value.Uint64(), signedTx.Value().Uint64())
			require.Equal(t, tp.Data, signedTx.Data())
			require.Equal(t, tp.BlobFeeCap.Uint64(), signedTx.BlobGasFeeCap().Uint64())
			require.Equal(t, tp.BlobHashes, signedTx.BlobHashes())
			require.Equal(t, tp.Sidecar, signedTx.BlobTxSidecar())

		}

	}

}

func TestNewWallet(t *testing.T) {

	//test data
	appid := "morph-tx-submitter-399A1722-3F2C-4E39-ABD2-1B65D02C66BA"
	rsaPrivStr := ""
	url := "http://localhost:8080/v1/sign/gen_address"
	chain := "QANET-L1"
	chainid := big.NewInt(900)
	signer := types.LatestSignerForChainID(chainid)

	rsaPriv, err := ParseRsaPrivateKey(rsaPrivStr)
	require.NoError(t, err)
	es := NewExternalSign(appid, rsaPriv, "", chain, signer)

	addr, err := es.RequestWalletAddr(url)
	require.NoError(t, err)
	require.NotEmpty(t, addr)
	t.Log("addr", addr)

}

func createEmptyBlobTxInner(withSidecar bool) *types.BlobTx {

	var (
		emptyBlob          = new(kzg4844.Blob)
		emptyBlobCommit, _ = kzg4844.BlobToCommitment(emptyBlob)
		emptyBlobProof, _  = kzg4844.ComputeBlobProof(emptyBlob, emptyBlobCommit)
		chainid            *uint256.Int
	)

	sidecar := &types.BlobTxSidecar{
		Blobs:       []kzg4844.Blob{*emptyBlob},
		Commitments: []kzg4844.Commitment{emptyBlobCommit},
		Proofs:      []kzg4844.Proof{emptyBlobProof},
	}
	blobtx := &types.BlobTx{
		ChainID:    chainid,
		Nonce:      uint64(23),
		GasTipCap:  uint256.MustFromBig(big.NewInt(1)),
		GasFeeCap:  uint256.MustFromBig(big.NewInt(1)),
		Gas:        23,
		To:         common.Address{0x03, 0x04, 0x05},
		Value:      uint256.NewInt(1),
		Data:       make([]byte, 50),
		BlobFeeCap: uint256.NewInt(15),
		BlobHashes: sidecar.BlobHashes(),
	}

	if withSidecar {
		blobtx.Sidecar = sidecar
	}
	return blobtx
}
