import SimpleAdmin from 0x%s
import NonFungibleToken from 0x631e88ae7f1d7c20

pub contract TRART: NonFungibleToken {

	pub var maxSupply: UInt64
	pub var totalSupply: UInt64
	pub var mintedNFTs: {UInt64 : {String : String}}
	pub var nonExclusiveNFTs: {UInt64 : Bool}

	pub event ContractInitialized()
	pub event Withdraw(id: UInt64, from: Address?)
	pub event Deposit(id: UInt64, to: Address?)
	pub event NFTNonExclusive(id: UInt64)

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
				TRART.nonExclusiveNFTs[withdrawID] != nil && TRART.nonExclusiveNFTs[withdrawID] == true : "This NFT is exclusive"
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

	pub fun setNonExclusive(id: UInt64, adminRef: &SimpleAdmin.Admin) {
		pre {
			adminRef.check(): "SimpleAdmin capability not valid"

			self.nonExclusiveNFTs[id] == nil : "NFT is already nonExclusive"
		}

		self.nonExclusiveNFTs[id] = true

		emit NFTNonExclusive(id: id)
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
		self.nonExclusiveNFTs = {}
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