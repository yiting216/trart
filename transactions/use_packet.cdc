import TRART from 0x%s
import SimpleAdmin from 0x%s
import NonFungibleToken from 0x631e88ae7f1d7c20

transaction(packetID: UInt64, artsID: [UInt64], metadatas: {UInt64: {String: String}}) {
    let receiverRef: &AnyResource{NonFungibleToken.CollectionPublic}

    let removeToken: @NonFungibleToken.NFT

    let minterRef: &TRART.NFTMinter

    prepare(admin: AuthAccount, acct: AuthAccount) {

        let adminRef = admin.borrow<&SimpleAdmin.Admin>(from: /storage/simpleAdmin)
            ?? panic("Could not borrow reference to the admin resource!")

        self.minterRef = admin.borrow<&TRART.NFTMinter>(from: /storage/TRARTNFTMinter)
            ?? panic("Could not borrow minter reference")

        let collectionRef = acct.borrow<&TRART.Collection>(from: /storage/TRARTNFTCollection)
            ?? panic("Could not borrow a reference to the owner's collection")

        self.receiverRef = acct.getCapability<&{NonFungibleToken.CollectionPublic}>(/public/TRARTNFTCollection)
            .borrow()
            ?? panic("Could not borrow receiver reference")

        self.removeToken <- collectionRef.withdrawWithAdminCheck(withdrawID: packetID, adminRef: adminRef)
    }

    execute {
        for id in artsID {
            let data = metadatas[id] ?? {} 
            self.minterRef.mintNFT(id: id, metadata: data, recipient: self.receiverRef)
        }

        destroy self.removeToken
    }
}