package test

const (
	_confPath = "./conf.json"

	_projectRootPath        = ".."
	_adminContractPath      = _projectRootPath + "/contracts/admin/SimpleAdmin.cdc"
	_nftContractPath        = _projectRootPath + "/contracts/nft/TRART.cdc"
	_setupAccountCdcPath    = _projectRootPath + "/transactions/setup_account.cdc"
	_mintNFTCdcPath         = _projectRootPath + "/transactions/mint_nft.cdc"
	_transferNFTCdcPath     = _projectRootPath + "/transactions/transfer_nft.cdc"
	_usePacketCdcPath       = _projectRootPath + "/transactions/use_packet.cdc"
	_queryAccountNFTCdcPath = _projectRootPath + "/scripts/read_collection_ids.cdc"
	_queryMintedNFTCdcPath  = _projectRootPath + "/scripts/read_minted_ids.cdc"

	_flowNetwork = "access.devnet.nodes.onflow.org:9000" //testnet
)
