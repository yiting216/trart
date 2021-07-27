package test

import (
	"fmt"
	"testing"

	"github.com/onflow/flow-go-sdk/templates"
)

//Deploy contracts to your admin account.
func TestDeployContract(t *testing.T) {
	//admin contract
	err1, txID1 := deployContract(templates.Contract{
		Name:   "SimpleAdmin",
		Source: _adminContract,
	})
	if err1 != nil {
		t.Error(err1)
		return
	}

	result1 := waitForSeal(txID1)
	if success := checkTxResult(result1); !success {
		t.Error(fmt.Sprintf("TestDeployContract --- transaction failed! txID: %s", txID1.String()))
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
		t.Error(err2)
		return
	}

	result2 := waitForSeal(txID2)
	if success := checkTxResult(result2); !success {
		t.Error(fmt.Sprintf("TestDeployContract --- transaction failed! txID: %s", txID2.String()))
		return
	}
}
