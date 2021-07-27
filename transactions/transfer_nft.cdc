import TRART from 0x%s
import SimpleAdmin from 0x%s
import NonFungibleToken from 0x631e88ae7f1d7c20

transaction(transferID: UInt64) {
    let receiverRef: &AnyResource{NonFungibleToken.CollectionPublic}

    let transferToken: @NonFungibleToken.NFT

    prepare(admin: AuthAccount, sender: AuthAccount, receiver: AuthAccount) {

        let adminRef = admin.borrow<&SimpleAdmin.Admin>(from: /storage/simpleAdmin)
            ?? panic("Could not borrow reference to the admin resource")

        let collectionRef = sender.borrow<&TRART.Collection>(from: /storage/TRARTNFTCollection)
            ?? panic("Could not borrow a reference to the owner's collection")

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

            log("Setup account completed")
        }

        self.receiverRef = receiverRef ?? panic("Could not borrow receiver reference")

        self.transferToken <- collectionRef.withdrawWithAdminCheck(withdrawID: transferID, adminRef: adminRef)
        log("TransferToken NFT completed")
    }

    execute {
        self.receiverRef.deposit(token: <-self.transferToken)
    }
}