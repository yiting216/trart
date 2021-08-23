package test

import (
	"fmt"
	"testing"
)

//Set specific id of NFT nonexclusive.
func TestSetNonExclusiveNFT(t *testing.T) {
	nftID := 1

	script := fmt.Sprintf(
		_setNonExclusiveNFTScript,
		_conf.Admin.Address,
		_conf.Admin.Address,
	)

	err, txID := setNonExclisiveNFT(
		script,
		uint(nftID),
	)
	if err != nil {
		t.Error(err)
		return
	}

	result := waitForSeal(txID)
	if success := checkTxResult(result); !success {
		t.Error(fmt.Sprintf("TestSetNonExclusiveNFT --- transaction failed! txID: %s", txID.String()))
		return
	}
}
