import TRART from 0x%s
import NonFungibleToken from 0x631e88ae7f1d7c20

transaction {
    prepare(acct: AuthAccount) {
        let collection <- TRART.createEmptyCollection()

        acct.save(<-collection, to: /storage/TRARTNFTCollection)

        acct.link<&{NonFungibleToken.CollectionPublic}>(
            /public/TRARTNFTCollection,
            target: /storage/TRARTNFTCollection
        )

        log("Setup account completed")
    }
}