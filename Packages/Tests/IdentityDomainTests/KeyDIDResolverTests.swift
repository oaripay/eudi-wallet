import CryptoKit
import Foundation
import IdentityDomain
import Testing

struct KeyDIDResolverTests {
    @Test("P-256 public key round trips through OARI-compatible did:key")
    func p256RoundTrip() async throws {
        let privateKey = P256.Signing.PrivateKey()
        let resolver = KeyDIDResolver()
        let did = try resolver.derive(publicKeyX963: privateKey.publicKey.x963Representation)
        let document = try await resolver.resolve(did)

        #expect(did.hasPrefix("did:key:z"))
        #expect(document.id == did)
        #expect(document.verificationMethod.count == 1)
        #expect(document.verificationMethod[0].publicKeyJwk.crv == "P-256")
        #expect(document.authentication == document.assertionMethod)
    }

    @Test("Malformed and unsupported key identifiers fail closed")
    func malformed() async {
        let resolver = KeyDIDResolver()
        await #expect(throws: DIDResolutionError.unsupportedMethod) {
            try await resolver.resolve("did:ebsi:test")
        }
        await #expect(throws: DIDResolutionError.malformedKey) {
            try await resolver.resolve("did:key:z0OIl")
        }
        await #expect(throws: DIDResolutionError.invalidDID) {
            try await resolver.resolve("did:key:z" + String(repeating: "1", count: 300))
        }
    }

    @Test("P-256 generator vector matches OARI p256-pub multicodec encoding")
    func oariCompatibilityVector() throws {
        let x963 = try #require(Data(hex: "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"))
        let did = try KeyDIDResolver().derive(publicKeyX963: x963)
        #expect(did == "did:key:zDnaepsL7AXenJkVYdkh5KuKsSU7Ykh7kyXaLLU7auN9FWSiZ")
    }

    @Test("Off-curve points and non-minimal multicodec varints reject")
    func malformedCanonicalEncoding() async {
        var offCurve = Data(repeating: 0, count: 65)
        offCurve[0] = 0x04
        #expect(throws: DIDResolutionError.malformedKey) {
            try KeyDIDResolver().derive(publicKeyX963: offCurve)
        }
        await #expect(throws: DIDResolutionError.malformedKey) {
            try await KeyDIDResolver().resolve(
                "did:key:zyexDvRXWGAnB73MayYtJcmdPVdYzx9L5XCXz5Ei7XU2PLGt2h"
            )
        }
    }
}

private extension Data {
    init?(hex: String) {
        guard hex.count.isMultiple(of: 2) else { return nil }
        var data = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index ..< next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        self = data
    }
}
