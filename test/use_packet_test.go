package test

import (
	"fmt"
	"testing"
)

//Transfer specific id of NFT from sender(account1) to receiver(account2).
func TestUsePacket(t *testing.T) {
	nftID := 1
	mintNFTs := []NFTData{
		{
			ID:       101,
			Metadata: make(map[string]interface{}),
		},
		{
			ID:       102,
			Metadata: make(map[string]interface{}),
		},
		{
			ID:       103,
			Metadata: make(map[string]interface{}),
		},
	}

	script := fmt.Sprintf(
		_usePacketScript,
		_conf.Admin.Address,
		_conf.Admin.Address,
	)

	err, txID := usePacket(
		script,
		_conf.Account2,
		uint(nftID),
		mintNFTs,
	)
	if err != nil {
		t.Error(err)
		return
	}

	result := waitForSeal(txID)
	if success := checkTxResult(result); !success {
		t.Error(fmt.Sprintf("TestUsePacket --- transaction failed! txID: %s", txID.String()))
		return
	}
}
