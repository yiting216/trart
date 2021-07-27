package test

import (
	"fmt"
	"testing"
)

//Transfer specific id of NFT from sender(account1) to receiver(account2).
func TestTransferNFT(t *testing.T) {
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
		t.Error(err)
		return
	}

	result := waitForSeal(txID)
	if success := checkTxResult(result); !success {
		t.Error(fmt.Sprintf("TestTransferNFT --- transaction failed! txID: %s", txID.String()))
		return
	}
}
