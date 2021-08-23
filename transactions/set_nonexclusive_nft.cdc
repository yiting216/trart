import TRART from 0x%s
import SimpleAdmin from 0x%s

transaction(id: UInt64) {
    let adminRef: &SimpleAdmin.Admin

    prepare(admin: AuthAccount) {

        self.adminRef = admin.borrow<&SimpleAdmin.Admin>(from: /storage/simpleAdmin)
            ?? panic("Could not borrow reference to the admin resource!")

    }

    execute {
        TRART.setNonExclusive(id: id, adminRef: self.adminRef)
        log("Set NFT nonExclusive completed")
    }
}