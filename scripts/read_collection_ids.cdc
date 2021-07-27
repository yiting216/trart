import NonFungibleToken from 0x631e88ae7f1d7c20

pub fun main() : [UInt64] {
    let nftOwner = getAccount(0x%s)

    var receiverRef = nftOwner.getCapability<&{NonFungibleToken.CollectionPublic}>(/public/TRARTNFTCollection)
        .borrow() 
        ?? panic("Could not borrow the receiver reference")

    return receiverRef.getIDs()
}