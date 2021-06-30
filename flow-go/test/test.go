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

const (
	_confPath = "./conf.json"

	_flowNetwork = "access.devnet.nodes.onflow.org:9000" //testnet
)

var (
	_conf confData

	_flowClient *client.Client
)

const (
	_adminContract = `
	pub contract SimpleAdmin {
		pub resource Admin {
			pub fun check(): Bool {
				return true
			}
		}

		init() {
			let admin <- create Admin()
			self.account.save(<-admin, to: /storage/simpleAdmin)
			self.account.link<&Admin>(/private/simpleAdminCapability, target: /storage/simpleAdmin)
		}
	}
	`

	_nftContract = `
	import SimpleAdmin from 0x%s
	import NonFungibleToken from 0x631e88ae7f1d7c20

	pub contract TRART: NonFungibleToken {
	
		pub var maxSupply: UInt64
		pub var totalSupply: UInt64
		pub var mintedNFTs: {UInt64 : {String : String}}
	
		pub event ContractInitialized()
		pub event Withdraw(id: UInt64, from: Address?)
		pub event Deposit(id: UInt64, to: Address?)

		pub resource NFT: NonFungibleToken.INFT {
			pub let id: UInt64
	
			pub var metadata: {String: String}
	
			init(initID: UInt64, initMetadata: {String: String}) {
				self.id = initID
				self.metadata = initMetadata
			}
		}
	
		pub resource Collection: NonFungibleToken.Provider, NonFungibleToken.Receiver, NonFungibleToken.CollectionPublic {
			pub var ownedNFTs: @{UInt64: NonFungibleToken.NFT}

			init () {
				self.ownedNFTs <- {}
			}
				
			pub fun withdraw(withdrawID: UInt64): @NonFungibleToken.NFT {
				pre {
					false : "Please call withdrawWithAdminCheck instead of withdraw"
				}

				let token <- self.ownedNFTs.remove(key: withdrawID) ?? panic("missing NFT")
	
				emit Withdraw(id: token.id, from: self.owner?.address)
	
				return <-token
			}

			pub fun withdrawWithAdminCheck(withdrawID: UInt64, adminRef: &SimpleAdmin.Admin): @NonFungibleToken.NFT {
				pre {
					adminRef.check(): "SimpleAdmin capability not valid"
				}

				let token <- self.ownedNFTs.remove(key: withdrawID) ?? panic("Missing NFT")
	
				emit Withdraw(id: token.id, from: self.owner?.address)
	
				return <-token
			}

			pub fun deposit(token: @NonFungibleToken.NFT) {
				let token <- token as! @TRART.NFT
	
				let id: UInt64 = token.id
	
				let oldToken <- self.ownedNFTs[id] <- token
	 
				emit Deposit(id: id, to: self.owner?.address)
	
				destroy oldToken
			}

			pub fun getIDs(): [UInt64] {
				return self.ownedNFTs.keys
			}

			pub fun borrowNFT(id: UInt64): &NonFungibleToken.NFT {
				return &self.ownedNFTs[id] as &NonFungibleToken.NFT
			}

			destroy() {
				destroy self.ownedNFTs
			}
		}
	
		pub fun createEmptyCollection(): @NonFungibleToken.Collection {
			return <- create Collection()
		}
	
		pub resource NFTMinter {
	
			pub fun mintNFT(id: UInt64, metadata: {String : String}, recipient: &AnyResource{NonFungibleToken.CollectionPublic}) {
				if TRART.totalSupply >= TRART.maxSupply {
					panic("Can not mint NFT any more")
				}

				if id <= 0 as UInt64 {
					panic("Can not mint invalid NFT id")
				}

				if TRART.mintedNFTs[id] != nil {
					panic("Can not mint existing NFT id")
				}
	
				var newNFT <- create NFT(initID: id, initMetadata: metadata)
	
				recipient.deposit(token: <-newNFT)
	
				TRART.totalSupply = TRART.totalSupply + 1 as UInt64
				TRART.mintedNFTs[id] = metadata

				log("Mint NFT completed")
			}

		}
	
		init() {
			self.mintedNFTs = {}
			self.maxSupply = 1000
			self.totalSupply = 0

			let collection <- self.createEmptyCollection()
			self.account.save(<-collection, to: /storage/TRARTNFTCollection)
	
			self.account.link<&{NonFungibleToken.CollectionPublic}>(
				/public/TRARTNFTCollection,
				target: /storage/TRARTNFTCollection
			)

			let minter <- create NFTMinter()
			self.account.save(<-minter, to: /storage/TRARTNFTMinter)

			
			emit ContractInitialized()
		}

	}
	`

	_setupAccountScript = `
	import TRART from 0x%s
	import NonFungibleToken from 0x631e88ae7f1d7c20

	transaction {
		prepare(acct: AuthAccount) {
			let collection <- TRART.createEmptyCollection()
	
			acct.save(<-collection, to: /storage/TRARTNFTCollection)

			acct.link<&{NonFungibleToken.CollectionPublic}>(
				/public/TRARTNFTCollection,
				target: /storage/TRARTNFTCollection
			)
	
			log("Setup account completed")
		}
	}
	`

	_mintNFTScript = `
	import TRART from 0x%s
	import NonFungibleToken from 0x631e88ae7f1d7c20

	transaction(mintID: UInt64, data: {String : String}) {
		let receiverRef: &AnyResource{NonFungibleToken.CollectionPublic}

		let minterRef: &TRART.NFTMinter

		prepare(minter: AuthAccount, receiver: AuthAccount) {

			self.minterRef = minter.borrow<&TRART.NFTMinter>(from: /storage/TRARTNFTMinter)
				?? panic("Could not borrow minter reference")

			var receiverRef = receiver.getCapability<&{NonFungibleToken.CollectionPublic}>(/public/TRARTNFTCollection)
				.borrow()
				?? nil
			if receiverRef == nil {
				let collection <- TRART.createEmptyCollection()
	
				receiver.save(<-collection, to: /storage/TRARTNFTCollection)
	
				receiver.link<&{NonFungibleToken.CollectionPublic}>(
					/public/TRARTNFTCollection,
					target: /storage/TRARTNFTCollection
				)
	
				receiverRef = receiver.getCapability<&{NonFungibleToken.CollectionPublic}>(/public/TRARTNFTCollection)
					.borrow()
					?? panic("Could not borrow receiver reference")
			}
	
			self.receiverRef = receiverRef ?? panic("Could not borrow receiver reference")
		}

		execute {
			self.minterRef.mintNFT(id: mintID, metadata: data, recipient: self.receiverRef)
		}
	}
	`

	_transferNFTScript = `
	import TRART from 0x%s
	import SimpleAdmin from 0x%s
	import NonFungibleToken from 0x631e88ae7f1d7c20

	transaction(transferID: UInt64) {
		let receiverRef: &AnyResource{NonFungibleToken.CollectionPublic}

		let transferToken: @NonFungibleToken.NFT

		prepare(admin: AuthAccount, sender: AuthAccount, receiver: AuthAccount) {

			let adminRef = admin.borrow<&SimpleAdmin.Admin>(from: /storage/simpleAdmin)
            	?? panic("Could not borrow reference to the admin resource")

			let collectionRef = sender.borrow<&TRART.Collection>(from: /storage/TRARTNFTCollection)
				?? panic("Could not borrow a reference to the owner's collection")

			var receiverRef = receiver.getCapability<&{NonFungibleToken.CollectionPublic}>(/public/TRARTNFTCollection)
				.borrow() 
				?? nil
				
			if receiverRef == nil {
				let collection <- TRART.createEmptyCollection()

				receiver.save(<-collection, to: /storage/TRARTNFTCollection)

				receiver.link<&{NonFungibleToken.CollectionPublic}>(
					/public/TRARTNFTCollection,
					target: /storage/TRARTNFTCollection
				)

				receiverRef = receiver.getCapability<&{NonFungibleToken.CollectionPublic}>(/public/TRARTNFTCollection)
					.borrow()
					?? panic("Could not borrow receiver reference")

				log("Setup account completed")
			}

			self.receiverRef = receiverRef ?? panic("Could not borrow receiver reference")

			self.transferToken <- collectionRef.withdrawWithAdminCheck(withdrawID: transferID, adminRef: adminRef)
			log("TransferToken NFT completed")
		}

		execute {
			self.receiverRef.deposit(token: <-self.transferToken)
		}
	}
	`

	_queryAccountNFTScript = `
	import NonFungibleToken from 0x631e88ae7f1d7c20

	pub fun main() : [UInt64] {
		let nftOwner = getAccount(0x%s)

		var receiverRef = nftOwner.getCapability<&{NonFungibleToken.CollectionPublic}>(/public/TRARTNFTCollection)
			.borrow() 
			?? panic("Could not borrow the receiver reference")

		return receiverRef.getIDs()
	}
	`

	_queryMintedNFTScript = `
	import TRART from 0x%s

	pub fun main() : [UInt64] {
		return TRART.mintedNFTs.keys
	}
	`
)

func init() {
	_conf = readConfig()

	_flowClient = newFlowClient()
}

// Step 1: Deploy contracts to your admin account. If contracts are exist, skip this step.
func TestDeployContract() {
	//admin contract
	err1, txID1 := deployContract(templates.Contract{
		Name:   "SimpleAdmin",
		Source: _adminContract,
	})
	if err1 != nil {
		log.Println(err1)
		return
	}

	result1 := waitForSeal(txID1)
	if success := checkTxResult(result1); !success {
		log.Printf("TestDeployContract --- transaction failed! txID: %s", txID1.String())
	}

	//nft contract
	err2, txID2 := deployContract(templates.Contract{
		Name: "TRART",
		Source: fmt.Sprintf(
			_nftContract,
			_conf.Admin.Address,
		),
	})
	if err2 != nil {
		log.Println(err2)
		return
	}

	result2 := waitForSeal(txID2)
	if success := checkTxResult(result2); !success {
		log.Printf("TestDeployContract --- transaction failed! txID: %s", txID2.String())
		return
	}
}

// Step 2: Mint specific id of NFT to receiver(account1).
func TestMintNFT() {
	nftID := 1
	data := make(map[string]interface{})
	data["name"] = "NFT"

	script := fmt.Sprintf(
		_mintNFTScript,
		_conf.Admin.Address,
	)

	err, txID := mintNFT(
		script,
		_conf.Account1,
		NFTData{
			ID:       uint(nftID),
			Metadata: data,
		},
	)
	if err != nil {
		log.Println(err)
		return
	}

	result := waitForSeal(txID)
	if success := checkTxResult(result); !success {
		log.Printf("TestMintNFT --- transaction failed! txID: %s", txID.String())
		return
	}
}

// Step 3: Transfer specific id of NFT from sender(account1) to receiver(account2).
func TestTransferNFT() {
	nftID := 1

	script := fmt.Sprintf(
		_transferNFTScript,
		_conf.Admin.Address,
		_conf.Admin.Address,
	)

	err, txID := transferNFT(
		script,
		_conf.Account1,
		_conf.Account2,
		uint(nftID),
	)
	if err != nil {
		log.Println(err)
		return
	}

	result := waitForSeal(txID)
	if success := checkTxResult(result); !success {
		log.Printf("TestTransferNFT --- transaction failed! txID: %s", txID.String())
		return
	}

}

// Query 1: Query specific address owned NFT.
func TestQueryOwnedNFT() {
	account := _conf.Account1

	script := fmt.Sprintf(
		_queryAccountNFTScript,
		account.Address,
	)

	err, value := queryOwnedNFT(
		script,
	)
	if err != nil {
		log.Println(err)
		return
	}

	fmt.Printf("TestQueryOwnedNFT --- %s owned NFT: %v", account.Address, value)
}

// Query 2: Query contract minted NFT.
func TestQueryMintedNFT() {
	script := fmt.Sprintf(
		_queryMintedNFTScript,
		_conf.Admin.Address,
	)

	err, value := queryMintedNFT(
		script,
	)
	if err != nil {
		log.Println(err)
		return
	}

	fmt.Printf("TestQueryMintedNFT --- minted NFT: %v", value)
}

func TestSetupAccount() {
	script := fmt.Sprintf(
		_setupAccountScript,
		_conf.Admin.Address,
	)

	err, txID := setupAccount(
		script,
		_conf.Account1,
	)
	if err != nil {
		log.Println(err)
		return
	}

	result := waitForSeal(txID)
	if success := checkTxResult(result); !success {
		log.Printf("TestSetupAccount --- transaction failed! txID: %s", txID.String())
		return
	}
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
			log.Println("mintNFT --- failed to sign transaction pay load")
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
