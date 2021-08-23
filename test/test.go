package test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/onflow/cadence"
	"github.com/onflow/flow-go-sdk"
	"github.com/onflow/flow-go-sdk/client"
	"github.com/onflow/flow-go-sdk/crypto"
	"github.com/onflow/flow-go-sdk/templates"
	"google.golang.org/grpc"
)

type account struct {
	Address string `json:"address"`
	PrivKey string `json:"privateKey"`
}

type confData struct {
	Admin    account `json:"admin"`
	Account1 account `json:"account1"`
	Account2 account `json:"account2"`
}

type NFTData struct {
	ID       uint
	Metadata map[string]interface{}
}

var (
	_conf confData

	_adminContract              string
	_nftContract                string
	_setupAccountScript         string
	_mintNFTScript              string
	_transferNFTScript          string
	_usePacketScript            string
	_setNonExclusiveNFTScript   string
	_queryAccountNFTScript      string
	_queryMintedNFTScript       string
	_queryNonExclusiveNFTScript string

	_flowClient *client.Client
)

func init() {
	_conf = readConfig()

	readCadenceFile()

	_flowClient = newFlowClient()
}

func deployContract(contract templates.Contract) (error, flow.Identifier) {
	var (
		resErr error
		txID   flow.Identifier
	)

	for {
		ctx := context.Background()
		flowClient := _flowClient

		block, err := flowClient.GetLatestBlock(ctx, true)
		if err != nil {
			log.Println("deployContract --- failed to get lastest block")
			resErr = err
			break
		}
		latestBlockID := block.ID

		serviceAcctAddr, serviceAcctKey, serviceSigner := getAccount(flowClient, _conf.Admin.Address, _conf.Admin.PrivKey)

		tx := templates.AddAccountContract(
			serviceAcctAddr,
			contract,
		).
			SetProposalKey(
				serviceAcctAddr,
				serviceAcctKey.Index,
				serviceAcctKey.SequenceNumber,
			).
			SetReferenceBlockID(latestBlockID).
			SetPayer(serviceAcctAddr)

		err = tx.SignEnvelope(serviceAcctAddr, serviceAcctKey.Index, serviceSigner)
		if err != nil {
			log.Println("deployContract --- failed to sign transaction envelope")
			resErr = err
			break
		}

		err = flowClient.SendTransaction(ctx, *tx)
		if err != nil {
			log.Println("deployContract --- failed to send transaction to network")
			resErr = err
			break
		}

		txID = tx.ID()

		fmt.Println("deployContract --- contract: \n", _adminContract)
		fmt.Println("deployContract --- send transaction txID: ", txID)
		break
	}

	return resErr, txID
}

func setupAccount(script string, receiverAccount account) (error, flow.Identifier) {
	var (
		resErr error
		txID   flow.Identifier
	)

	fmt.Println(script)

	for {
		ctx := context.Background()
		flowClient := _flowClient

		block, err := flowClient.GetLatestBlock(ctx, true)
		if err != nil {
			log.Println("setupAccount --- failed to get lastest block")
			resErr = err
			break
		}
		latestBlockID := block.ID

		serviceAcctAddr, serviceAcctKey, serviceSigner := getAccount(flowClient, _conf.Admin.Address, _conf.Admin.PrivKey)
		receiverAcctAddr, receiverAcctKey, receiverSigner := getAccount(flowClient, receiverAccount.Address, receiverAccount.PrivKey)

		tx := flow.NewTransaction().
			SetScript([]byte(script)).
			SetGasLimit(100).
			SetProposalKey(serviceAcctAddr, serviceAcctKey.Index, serviceAcctKey.SequenceNumber).
			SetReferenceBlockID(latestBlockID).
			SetPayer(serviceAcctAddr).
			AddAuthorizer(receiverAcctAddr)

		if err := tx.SignPayload(receiverAcctAddr, receiverAcctKey.Index, receiverSigner); err != nil {
			log.Println("setupAccount --- failed to sign transaction pay load")
			resErr = err
			break
		}

		if err := tx.SignEnvelope(serviceAcctAddr, serviceAcctKey.Index, serviceSigner); err != nil {
			log.Println("setupAccount --- failed to sign transaction envelope")
			resErr = err
			break
		}

		if err = flowClient.SendTransaction(ctx, *tx); err != nil {
			log.Println("setupAccount --- failed to send transaction to network")
			resErr = err
			break
		}

		txID = tx.ID()
		fmt.Println("setupAccount --- send transaction txID: ", txID)
		break
	}

	return resErr, txID
}

func mintNFT(script string, receiverAccount account, mintNFT NFTData) (error, flow.Identifier) {
	var (
		resErr error
		txID   flow.Identifier
	)

	fmt.Println(script)

	for {
		ctx := context.Background()
		flowClient := _flowClient

		block, err := flowClient.GetLatestBlock(ctx, true)
		if err != nil {
			log.Println("mintNFT --- failed to get lastest block")
			resErr = err
			break
		}
		latestBlockID := block.ID

		serviceAcctAddr, serviceAcctKey, serviceSigner := getAccount(flowClient, _conf.Admin.Address, _conf.Admin.PrivKey)
		receiverAcctAddr, receiverAcctKey, receiverSigner := getAccount(flowClient, receiverAccount.Address, receiverAccount.PrivKey)

		tx := flow.NewTransaction().
			SetScript([]byte(script)).
			SetGasLimit(100).
			SetProposalKey(serviceAcctAddr, serviceAcctKey.Index, serviceAcctKey.SequenceNumber).
			SetReferenceBlockID(latestBlockID).
			SetPayer(serviceAcctAddr).
			AddAuthorizer(serviceAcctAddr).
			AddAuthorizer(receiverAcctAddr)

		nftID := cadence.NewUInt64(uint64(mintNFT.ID))
		if err := tx.AddArgument(nftID); err != nil {
			log.Println("mintNFT --- failed to AddArgument nftID: ", nftID)
			resErr = err
			break
		}

		datas := make([]cadence.KeyValuePair, 0)
		for k, v := range mintNFT.Metadata {
			key, err := cadence.NewValue(k)
			if err != nil {
				log.Println(err)
				continue
			}

			value, err := cadence.NewValue(v)
			if err != nil {
				log.Println(err)
				continue
			}

			datas = append(datas, cadence.KeyValuePair{
				Key:   key,
				Value: value,
			})
		}
		nftData := cadence.NewDictionary(datas)
		if err := tx.AddArgument(nftData); err != nil {
			log.Println("mintNFT --- failed to AddArgument nftData: ", nftData)
			resErr = err
			break
		}

		if err := tx.SignPayload(receiverAcctAddr, receiverAcctKey.Index, receiverSigner); err != nil {
			log.Println("mintNFT --- failed to sign transaction pay load")
			resErr = err
			break
		}

		if err := tx.SignEnvelope(serviceAcctAddr, serviceAcctKey.Index, serviceSigner); err != nil {
			log.Println("mintNFT --- failed to sign transaction envelope")
			resErr = err
			break
		}

		if err = flowClient.SendTransaction(ctx, *tx); err != nil {
			log.Println("mintNFT --- failed to send transaction to network")
			resErr = err
			break
		}

		txID = tx.ID()
		fmt.Println("mintNFT --- send transaction txID: ", txID)
		break
	}

	return resErr, txID
}

func transferNFT(script string, senderAccount, receiverAccount account, id uint) (error, flow.Identifier) {
	var (
		resErr error
		txID   flow.Identifier
	)

	fmt.Println(script)

	for {
		ctx := context.Background()
		flowClient := _flowClient

		block, err := flowClient.GetLatestBlock(ctx, true)
		if err != nil {
			log.Println("transferNFT --- failed to get lastest block")
			resErr = err
			break
		}
		latestBlockID := block.ID

		serviceAcctAddr, serviceAcctKey, serviceSigner := getAccount(flowClient, _conf.Admin.Address, _conf.Admin.PrivKey)
		senderAcctAddr, senderAcctKey, senderSigner := getAccount(flowClient, senderAccount.Address, senderAccount.PrivKey)
		receiverAcctAddr, receiverAcctKey, receiverSigner := getAccount(flowClient, receiverAccount.Address, receiverAccount.PrivKey)

		tx := flow.NewTransaction().
			SetScript([]byte(script)).
			SetGasLimit(100).
			SetProposalKey(serviceAcctAddr, serviceAcctKey.Index, serviceAcctKey.SequenceNumber).
			SetReferenceBlockID(latestBlockID).
			SetPayer(serviceAcctAddr).
			AddAuthorizer(serviceAcctAddr).
			AddAuthorizer(senderAcctAddr).
			AddAuthorizer(receiverAcctAddr)

		nftID := cadence.NewUInt64(uint64(id))

		if err := tx.AddArgument(nftID); err != nil {
			log.Println("transferNFT --- failed to AddArgument nftID: ", nftID)
			resErr = err
			break
		}

		if err := tx.SignPayload(senderAcctAddr, senderAcctKey.Index, senderSigner); err != nil {
			log.Println("transferNFT --- failed to sign transaction pay load")
			resErr = err
			break
		}

		if err := tx.SignPayload(receiverAcctAddr, receiverAcctKey.Index, receiverSigner); err != nil {
			log.Println("transferNFT --- failed to sign transaction envelope")
			resErr = err
			break
		}

		if err := tx.SignEnvelope(serviceAcctAddr, serviceAcctKey.Index, serviceSigner); err != nil {
			log.Println("transferNFT --- failed to sign transaction envelope")
			resErr = err
			break
		}

		if err = flowClient.SendTransaction(ctx, *tx); err != nil {
			log.Println("transferNFT --- failed to send transaction to network")
			resErr = err
			break
		}

		txID = tx.ID()
		fmt.Println("transferNFT --- send transaction txID: ", txID)
		break
	}

	return resErr, txID
}

func usePacket(script string, receiverAccount account, id uint, mintNFTs []NFTData) (error, flow.Identifier) {
	var (
		resErr error
		txID   flow.Identifier
	)

	fmt.Println(script)

	for {
		ctx := context.Background()
		flowClient := _flowClient

		block, err := flowClient.GetLatestBlock(ctx, true)
		if err != nil {
			log.Println("usePacket --- failed to get lastest block")
			resErr = err
			break
		}
		latestBlockID := block.ID

		serviceAcctAddr, serviceAcctKey, serviceSigner := getAccount(flowClient, _conf.Admin.Address, _conf.Admin.PrivKey)
		receiverAcctAddr, receiverAcctKey, receiverSigner := getAccount(flowClient, receiverAccount.Address, receiverAccount.PrivKey)

		tx := flow.NewTransaction().
			SetScript([]byte(script)).
			SetGasLimit(100).
			SetProposalKey(serviceAcctAddr, serviceAcctKey.Index, serviceAcctKey.SequenceNumber).
			SetReferenceBlockID(latestBlockID).
			SetPayer(serviceAcctAddr).
			AddAuthorizer(serviceAcctAddr).
			AddAuthorizer(receiverAcctAddr)

		nftID := cadence.NewUInt64(uint64(id))
		if err := tx.AddArgument(nftID); err != nil {
			log.Println("usePacket --- failed to AddArgument nftID: ", nftID)
			resErr = err
			break
		}

		ids := make([]cadence.Value, 0)
		datas := make([]cadence.KeyValuePair, 0)
		for _, nft := range mintNFTs {
			//ID
			id := cadence.NewUInt64(uint64(nft.ID))
			ids = append(ids, id)

			//Metadata
			m := make([]cadence.KeyValuePair, 0)
			for k, v := range nft.Metadata {
				key, err := cadence.NewValue(k)
				if err != nil {
					log.Println(err)
					continue
				}

				value, err := cadence.NewValue(v)
				if err != nil {
					log.Println(err)
					continue
				}

				m = append(m, cadence.KeyValuePair{
					Key:   key,
					Value: value,
				})
			}

			if len(m) > 0 {
				key := id
				value := cadence.NewDictionary(m)

				datas = append(datas, cadence.KeyValuePair{
					Key:   key,
					Value: value,
				})
			}
		}

		nftIDs := cadence.NewArray(ids)
		if err := tx.AddArgument(nftIDs); err != nil {
			log.Println("usePacket --- failed to AddArgument nftIDs: ", nftIDs)
			resErr = err
			break
		}

		nftDatas := cadence.NewDictionary(datas)
		if err := tx.AddArgument(nftDatas); err != nil {
			log.Println("usePacket --- failed to AddArgument nftDatas: ", nftDatas)
			resErr = err
			break
		}

		if err := tx.SignPayload(receiverAcctAddr, receiverAcctKey.Index, receiverSigner); err != nil {
			log.Println("usePacket --- failed to sign transaction envelope")
			resErr = err
			break
		}

		if err := tx.SignEnvelope(serviceAcctAddr, serviceAcctKey.Index, serviceSigner); err != nil {
			log.Println("usePacket --- failed to sign transaction envelope")
			resErr = err
			break
		}

		if err = flowClient.SendTransaction(ctx, *tx); err != nil {
			log.Println("usePacket --- failed to send transaction to network")
			resErr = err
			break
		}

		txID = tx.ID()
		fmt.Println("usePacket --- send transaction txID: ", txID)
		break
	}

	return resErr, txID
}

func setNonExclisiveNFT(script string, id uint) (error, flow.Identifier) {
	var (
		resErr error
		txID   flow.Identifier
	)

	fmt.Println(script)

	for {
		ctx := context.Background()
		flowClient := _flowClient

		block, err := flowClient.GetLatestBlock(ctx, true)
		if err != nil {
			log.Println("setNonExclisiveNFT --- failed to get lastest block")
			resErr = err
			break
		}
		latestBlockID := block.ID

		serviceAcctAddr, serviceAcctKey, serviceSigner := getAccount(flowClient, _conf.Admin.Address, _conf.Admin.PrivKey)

		tx := flow.NewTransaction().
			SetScript([]byte(script)).
			SetGasLimit(100).
			SetProposalKey(serviceAcctAddr, serviceAcctKey.Index, serviceAcctKey.SequenceNumber).
			SetReferenceBlockID(latestBlockID).
			SetPayer(serviceAcctAddr).
			AddAuthorizer(serviceAcctAddr)

		nftID := cadence.NewUInt64(uint64(id))

		if err := tx.AddArgument(nftID); err != nil {
			log.Println("setNonExclisiveNFT --- failed to AddArgument nftID: ", nftID)
			resErr = err
			break
		}

		if err := tx.SignEnvelope(serviceAcctAddr, serviceAcctKey.Index, serviceSigner); err != nil {
			log.Println("setNonExclisiveNFT --- failed to sign transaction envelope")
			resErr = err
			break
		}

		if err = flowClient.SendTransaction(ctx, *tx); err != nil {
			log.Println("setNonExclisiveNFT --- failed to send transaction to network")
			resErr = err
			break
		}

		txID = tx.ID()
		fmt.Println("setNonExclisiveNFT --- send transaction txID: ", txID)
		break
	}

	return resErr, txID
}

func queryOwnedNFT(script string) (error, cadence.Value) {
	var (
		resErr error
		v      cadence.Value
	)

	fmt.Println(script)

	for {
		ctx := context.Background()
		flowClient := _flowClient

		value, err := flowClient.ExecuteScriptAtLatestBlock(ctx, []byte(script), nil)
		if err != nil {
			log.Println("queryOwnedNFT --- failed to execute script")
			resErr = err
			break
		}

		v = value
		break
	}

	return resErr, v
}

func queryMintedNFT(script string) (error, cadence.Value) {
	var (
		resErr error
		v      cadence.Value
	)

	fmt.Println(script)

	for {
		ctx := context.Background()
		flowClient := _flowClient

		value, err := flowClient.ExecuteScriptAtLatestBlock(ctx, []byte(script), nil)
		if err != nil {
			log.Println("queryMintedNFT --- failed to execute script")
			resErr = err
			break
		}

		v = value
		break
	}

	return resErr, v
}

func queryNonExclusiveNFT(script string) (error, cadence.Value) {
	var (
		resErr error
		v      cadence.Value
	)

	fmt.Println(script)

	for {
		ctx := context.Background()
		flowClient := _flowClient

		value, err := flowClient.ExecuteScriptAtLatestBlock(ctx, []byte(script), nil)
		if err != nil {
			log.Println("queryNonExclusiveNFT --- failed to execute script")
			resErr = err
			break
		}

		v = value
		break
	}

	return resErr, v
}

func newFlowClient() *client.Client {
	flowClient, err := client.New(_flowNetwork, grpc.WithInsecure())
	if err != nil {
		panic(err)
	}

	return flowClient
}

func getAccount(flowClient *client.Client, address, priveKey string) (flow.Address, *flow.AccountKey, crypto.Signer) {
	servicePrivateKeySigAlgo := crypto.StringToSignatureAlgorithm(crypto.ECDSA_P256.String())
	servicePrivateKeyHex := priveKey
	privateKey, err := crypto.DecodePrivateKeyHex(servicePrivateKeySigAlgo, servicePrivateKeyHex)
	if err != nil {
		panic(err)
	}

	addr := flow.HexToAddress(address)
	acc, err := flowClient.GetAccount(context.Background(), addr)
	if err != nil {
		panic(err)
	}

	accountKey := acc.Keys[0]
	signer := crypto.NewInMemorySigner(privateKey, accountKey.HashAlgo)

	return addr, accountKey, signer
}

func waitForSeal(id flow.Identifier) (result *flow.TransactionResult) {
	var err error

	for {
		ctx := context.Background()
		c := _flowClient

		result, err = c.GetTransactionResult(ctx, id)
		if err != nil {
			log.Println(err)
			break
		}

		if result.Status != flow.TransactionStatusUnknown {
			for result.Status != flow.TransactionStatusSealed {
				time.Sleep(time.Second)

				if result, err = c.GetTransactionResult(ctx, id); err != nil {
					log.Println(err)
					break
				}
			}
		}

		break
	}

	return result
}

func checkTxResult(result *flow.TransactionResult) bool {
	success := false
	for {
		if result == nil {
			break
		}

		if result.Status != flow.TransactionStatusSealed {
			log.Println("checkTxResult --- tx result status is not TransactionStatusSealed")
			break
		}

		if result.Error != nil {
			log.Println(result.Error)
			break
		}

		success = true
		break
	}

	return success
}

func ReadFile(path string) string {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	return string(contents)
}

func readConfig() confData {
	fcontent := ReadFile(_confPath)
	if len(fcontent) == 0 {
		panic("Conf content is empty")
	}

	conf := confData{}
	if err := json.Unmarshal([]byte(fcontent), &conf); err != nil {
		panic(err)
	}

	return conf
}

func readCadenceFile() {
	//contracts
	{
		content := ReadFile(_adminContractPath)
		if len(content) == 0 {
			panic(fmt.Sprintf("File content is empty %s", _adminContractPath))
		}

		_adminContract = content
	}
	{
		content := ReadFile(_nftContractPath)
		if len(content) == 0 {
			panic(fmt.Sprintf("File content is empty %s", _nftContractPath))
		}

		_nftContract = content
	}

	//transactions
	{
		content := ReadFile(_setupAccountCdcPath)
		if len(content) == 0 {
			panic(fmt.Sprintf("File content is empty %s", _setupAccountCdcPath))
		}

		_setupAccountScript = content
	}
	{
		content := ReadFile(_mintNFTCdcPath)
		if len(content) == 0 {
			panic(fmt.Sprintf("File content is empty %s", _mintNFTCdcPath))
		}

		_mintNFTScript = content
	}
	{
		content := ReadFile(_transferNFTCdcPath)
		if len(content) == 0 {
			panic(fmt.Sprintf("File content is empty %s", _transferNFTCdcPath))
		}

		_transferNFTScript = content
	}
	{
		content := ReadFile(_usePacketCdcPath)
		if len(content) == 0 {
			panic(fmt.Sprintf("File content is empty %s", _usePacketCdcPath))
		}

		_usePacketScript = content
	}
	{
		content := ReadFile(_setNonExclusiveNFTCdcPath)
		if len(content) == 0 {
			panic(fmt.Sprintf("File content is empty %s", _setNonExclusiveNFTCdcPath))
		}

		_setNonExclusiveNFTScript = content
	}

	//scripts
	{
		content := ReadFile(_queryAccountNFTCdcPath)
		if len(content) == 0 {
			panic(fmt.Sprintf("File content is empty %s", _queryAccountNFTCdcPath))
		}

		_queryAccountNFTScript = content
	}
	{
		content := ReadFile(_queryMintedNFTCdcPath)
		if len(content) == 0 {
			panic(fmt.Sprintf("File content is empty %s", _queryMintedNFTCdcPath))
		}

		_queryMintedNFTScript = content
	}
	{
		content := ReadFile(_queryNonExclusiveNFTCdcPath)
		if len(content) == 0 {
			panic(fmt.Sprintf("File content is empty %s", _queryNonExclusiveNFTCdcPath))
		}

		_queryNonExclusiveNFTScript = content
	}

}
