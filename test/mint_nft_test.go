package test

import (
	"fmt"
	"testing"
)

//Mint specific id of NFT to receiver(account1).
func TestMintNFT(t *testing.T) {
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
		t.Error(err)
		return
	}

	result := waitForSeal(txID)
	if success := checkTxResult(result); !success {
		t.Error(fmt.Sprintf("TestMintNFT --- transaction failed! txID: %s", txID.String()))
		return
	}
}
