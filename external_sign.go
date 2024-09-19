package externalsign

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/common/hexutil"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/log"
)

type ExternalSign struct {
	Appid   string
	Address string
	Privkey *rsa.PrivateKey
	Chain   string

	// http client
	Client *resty.Client

	Signer types.Signer
}

type BusinessData struct {
	Appid     string `json:"appid"`
	Data      string `json:"data"`
	Noncestr  string `json:"noncestr"`
	Timestamp string `json:"timestamp"`
}

type ReqData struct {
	BusinessData
	BizSignature string `json:"bizSignature"`
	Pubkey       string `json:"publicKey"`
	TxData       string `json:"txData"` // hex string of marshaled tx
}

type Data struct {
	Address string `json:"address"`
	Chain   string `json:"chain"`
	Sha3    string `json:"sha3"`
}
type GenAddrData struct {
	CoinId      string `json:"coinId"`
	ChainCoinId string `json:"chainCoinId"`
	EncryptKey  string `json:"encryptKey"`
	KeyMd5      string `json:"keyMd5"`
	UniqId      string `json:"uniqId"`
	Chain       string `json:"chain"`
}

func init() {
	output := io.Writer(os.Stdout)
	logHandler := log.StreamHandler(output, log.TerminalFormat(false))
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlDebug, logHandler))
}

func NewExternalSign(appid string, priv *rsa.PrivateKey, addr, chain string, signer types.Signer) *ExternalSign {

	// new resty.client
	client := resty.New()
	return &ExternalSign{
		Appid:   appid,
		Privkey: priv,
		Client:  client,
		Address: addr,
		Chain:   chain,
		Signer:  signer,
	}
}

func (e *ExternalSign) newData(hash string) (*Data, error) {

	return &Data{
		Address: e.Address,
		Chain:   e.Chain,
		Sha3:    hash,
	}, nil
}

func (e *ExternalSign) NewGenAddrData() *GenAddrData {
	return &GenAddrData{
		Chain: e.Chain,
	}
}

func (e *ExternalSign) craftReqData(data interface{}, txinfo string) (*ReqData, error) {
	nonceStr := uuid.NewString()
	dataBs, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal data failed: %w", err)
	}
	businessData := BusinessData{
		Appid:     e.Appid,
		Data:      string(dataBs),
		Noncestr:  nonceStr,
		Timestamp: strconv.FormatInt(time.Now().UnixMilli(), 10),
	}
	businessDataBs, err := json.Marshal(businessData)
	if err != nil {
		return nil, fmt.Errorf("marshal data failed: %w", err)
	}
	hashed := sha256.Sum256([]byte(businessDataBs))
	signature, err := rsa.SignPKCS1v15(nil, e.Privkey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("sign data failed: %w", err)
	}
	hexSig := hex.EncodeToString(signature)

	pubkey, err := GetPubKeyStr(e.Privkey)
	if err != nil {
		return nil, fmt.Errorf("GetPubKeyStr err:%w", err)
	}
	return &ReqData{
		BusinessData: businessData,
		BizSignature: hexSig,
		Pubkey:       pubkey,
		TxData:       txinfo,
	}, nil

}

// request external sign
// params: unsigned tx
// return: signed tx
func (e *ExternalSign) RequestSign(url string, tx *types.Transaction) (*types.Transaction, error) {
	hashHex := e.Signer.Hash(tx).Hex()

	data, err := e.newData(hashHex)
	if err != nil {
		return nil, fmt.Errorf("new data error:%s", err)
	}

	// txinfo
	txBs, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal tx failed:%w", err)
	}

	reqdata, err := e.craftReqData(*data, hex.EncodeToString(txBs))
	if err != nil {
		return nil, fmt.Errorf("craft req data error:%s", err)
	}

	resp, err := e.doRequest(url, reqdata)
	if err != nil {
		return nil, fmt.Errorf("doRequest err: %w", err)
	}

	// decode resp
	response := new(Response)
	err = json.Unmarshal(resp.Body(), response)
	if err != nil {
		return nil, fmt.Errorf("unmarshal resp err:%w", err)
	}

	if len(response.Result.SignDatas) == 0 {
		return nil, errors.New("respones sha3 empty")
	}

	sig, err := hexutil.Decode(response.Result.SignDatas[0].Sign)
	if err != nil {
		return nil, fmt.Errorf("decode sig failed:%w", err)
	}
	signedTx, err := tx.WithSignature(e.Signer, sig)
	if err != nil {
		return nil, fmt.Errorf("with signature err:%w", err)
	}
	return signedTx, nil
}

func (e *ExternalSign) RequestWalletAddr(url string) (*common.Address, error) {
	data := e.NewGenAddrData()
	reqData, err := e.craftReqData(data, "")
	if err != nil {
		return nil, fmt.Errorf("craftReqData err:%w", err)
	}

	resp, err := e.doRequest(url, reqData)
	if err != nil {
		return nil, fmt.Errorf("doRequest err: %w", err)
	}

	// decode resp
	response := new(Response)
	err = json.Unmarshal(resp.Body(), response)
	if err != nil {
		return nil, fmt.Errorf("unmarshal resp err:%w", err)
	}

	if len(response.Result.Address) == 0 {
		return nil, errors.New("response address empty")
	}

	addr := common.HexToAddress(response.Result.Address)
	return &addr, nil
}

func (e *ExternalSign) doRequest(url string, payload interface{}) (*resty.Response, error) {

	log.Info("req info", "payload", payload)

	resp, err := e.Client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(payload).
		Post(url)

	if err != nil {
		return nil, fmt.Errorf("request sign error: %v", err)
	}

	// log resp info
	log.Info("response info",
		"status", resp.StatusCode(),
		"body", resp.String(),
	)

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("response status not ok: %v, resp body:%v", resp.StatusCode(), string(resp.Body()))
	}
	return resp, nil
}
