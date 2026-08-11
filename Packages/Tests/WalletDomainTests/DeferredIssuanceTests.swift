import Foundation
import Testing
import WalletDomain

struct DeferredIssuanceTests {
    @Test("Deferred envelope round trips opaque continuation and scheduling state")
    func roundTrip() throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let value = DeferredIssuance(
            continuation: Data([0, 1, 2, 255]),
            issuerIdentifier: "https://issuer.example",
            configurationIDs: ["pid", "email"],
            displayName: "Identity credentials",
            nextAttemptAt: now.addingTimeInterval(30),
            attempts: 2,
            state: .authorizationRequired,
            createdAt: now,
            updatedAt: now.addingTimeInterval(10)
        )

        let restored = try JSONDecoder().decode(
            DeferredIssuance.self,
            from: JSONEncoder().encode(value)
        )
        #expect(restored == value)
    }
}
