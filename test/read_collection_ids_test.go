package test

import (
	"fmt"
	"testing"
)

//Query specific address owned NFT.
func TestQueryOwnedNFT(t *testing.T) {
	account := _conf.Account1

	script := fmt.Sprintf(
		_queryAccountNFTScript,
		account.Address,
	)

	err, value := queryOwnedNFT(
		script,
	)
	if err != nil {
		t.Error(err)
		return
	}

	t.Logf("TestQueryOwnedNFT --- %s owned NFT: %v", account.Address, value)
}
