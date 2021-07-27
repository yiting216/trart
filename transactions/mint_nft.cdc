import TRART from 0x%s
import NonFungibleToken from 0x631e88ae7f1d7c20

transaction(mintID: UInt64, data: {String : String}) {
    let receiverRef: &AnyResource{NonFungibleToken.CollectionPublic}

    let minterRef: &TRART.NFTMinter

    prepare(minter: AuthAccount, receiver: AuthAccount) {

        self.minterRef = minter.borrow<&TRART.NFTMinter>(from: /storage/TRARTNFTMinter)
            ?? panic("Could not borrow minter reference")

        var receiverRef = receiver.getCapability<&{NonFungibleToken.CollectionPublic}>(/public/TRARTNFTCollection)
            .borrow()
            ?? nil
        if receiverRef == nil {
            let collection <- TRART.createEmptyCollection()

            receiver.save(<-collection, to: /storage/TRARTNFTCollection)

            receiver.link<&{NonFungibleToken.CollectionPublic}>(
                /public/TRARTNFTCollection,
                target: /storage/TRARTNFTCollection
            )

            receiverRef = receiver.getCapability<&{NonFungibleToken.CollectionPublic}>(/public/TRARTNFTCollection)
                .borrow()
                ?? panic("Could not borrow receiver reference")
        }

        self.receiverRef = receiverRef ?? panic("Could not borrow receiver reference")
    }

    execute {
        self.minterRef.mintNFT(id: mintID, metadata: data, recipient: self.receiverRef)
    }
}