pub contract SimpleAdmin {
    pub resource Admin {
        pub fun check(): Bool {
            return true
        }
    }

    init() {
        let admin <- create Admin()
        self.account.save(<-admin, to: /storage/simpleAdmin)
        self.account.link<&Admin>(/private/simpleAdminCapability, target: /storage/simpleAdmin)
    }
}