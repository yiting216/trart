package test

import (
	"fmt"
	"testing"
)

//Query contract minted NFT.
func TestQueryMintedNFT(t *testing.T) {
	script := fmt.Sprintf(
		_queryMintedNFTScript,
		_conf.Admin.Address,
	)

	err, value := queryMintedNFT(
		script,
	)
	if err != nil {
		t.Error(err)
		return
	}

	t.Logf("TestQueryMintedNFT --- minted NFT: %v", value)
}
