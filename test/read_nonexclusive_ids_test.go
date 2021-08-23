package test

import (
	"fmt"
	"testing"
)

//Query contract nonexclusive NFT.
func TestQueryNonExclusiveNFT(t *testing.T) {
	script := fmt.Sprintf(
		_queryNonExclusiveNFTScript,
		_conf.Admin.Address,
	)

	err, value := queryNonExclusiveNFT(
		script,
	)
	if err != nil {
		t.Error(err)
		return
	}

	t.Logf("TestQueryNonExclusiveNFT --- nonexclusive NFT: %v", value)
}
