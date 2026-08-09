import CryptoKit
import EbsiW3CBackend
import Foundation
import IdentityDomain
import Testing

struct HTTPSIssuerKeyDiscoveryTests {
    private let issuer = "https://oid4vc.igrant.io/organisation/test/service/draft-17"

    @Test("HTTPS SD-JWT issuer resolves ES256 key from OpenID metadata JWKS")
    func resolvesOpenIDJWKS() async throws {
        let key = P256.Signing.PrivateKey()
        let transport = HTTPSIssuerFixtureTransport(issuer: issuer, publicKey: key.publicKey)
        let validator = NativeW3CCredentialValidator(
            resolver: RejectingDIDResolver(),
            transport: transport
        )
        let credential = try signedSDJWT(key: key, kid: "igrant-signing-key")

        let signedIssuer = try await validator.validate(
            rawCredential: Data(credential.utf8),
            profile: .dcSdJWTVC(),
            expectedIssuer: issuer,
            expectedHolderDID: "did:key:unused",
            at: Date(timeIntervalSince1970: 1_800_000_000)
        )
        #expect(signedIssuer == issuer)

        let paths = await transport.requestPaths
        #expect(paths == [
            "/.well-known/jwt-vc-issuer/organisation/test/service/draft-17",
            "/.well-known/oauth-authorization-server/organisation/test/service/draft-17",
            "/organisation/test/service/jwks",
        ])
    }

    @Test("HTTPS issuer metadata cannot substitute a different issuer")
    func rejectsIssuerSubstitution() async throws {
        let key = P256.Signing.PrivateKey()
        let transport = HTTPSIssuerFixtureTransport(
            issuer: issuer,
            publicKey: key.publicKey,
            metadataIssuer: "https://attacker.example"
        )
        let validator = NativeW3CCredentialValidator(
            resolver: RejectingDIDResolver(),
            transport: transport
        )
        let credential = try signedSDJWT(key: key, kid: "igrant-signing-key")

        await #expect(throws: EbsiCredentialError.issuerSigningKeysUnresolved) {
            try await validator.validate(
                rawCredential: Data(credential.utf8),
                profile: .dcSdJWTVC(),
                expectedIssuer: issuer,
                expectedHolderDID: "did:key:unused",
                at: Date(timeIntervalSince1970: 1_800_000_000)
            )
        }
        #expect(await transport.requestPaths.contains { $0.hasSuffix("/service/jwks") } == false)
    }

    @Test("HTTPS issuer metadata must identify its issuer")
    func rejectsIssuerlessMetadata() async throws {
        let key = P256.Signing.PrivateKey()
        let transport = HTTPSIssuerFixtureTransport(
            issuer: issuer,
            publicKey: key.publicKey,
            includesMetadataIssuer: false
        )
        let validator = NativeW3CCredentialValidator(
            resolver: RejectingDIDResolver(),
            transport: transport
        )
        let credential = try signedSDJWT(key: key, kid: "igrant-signing-key")

        await #expect(throws: EbsiCredentialError.issuerSigningKeysUnresolved) {
            try await validator.validate(
                rawCredential: Data(credential.utf8),
                profile: .dcSdJWTVC(),
                expectedIssuer: issuer,
                expectedHolderDID: "did:key:unused",
                at: Date(timeIntervalSince1970: 1_800_000_000)
            )
        }
        #expect(await transport.requestPaths.contains { $0.hasSuffix("/service/jwks") } == false)
    }

    @Test("Credential issuer must match the reviewed offer issuer")
    func rejectsCredentialIssuerSubstitution() async throws {
        let key = P256.Signing.PrivateKey()
        let transport = HTTPSIssuerFixtureTransport(issuer: issuer, publicKey: key.publicKey)
        let validator = NativeW3CCredentialValidator(
            resolver: RejectingDIDResolver(),
            transport: transport
        )
        let credential = try signedSDJWT(key: key, kid: "igrant-signing-key")

        await #expect(throws: EbsiCredentialError.issuerMismatch) {
            try await validator.validate(
                rawCredential: Data(credential.utf8),
                profile: .dcSdJWTVC(),
                expectedIssuer: "https://reviewed-issuer.example",
                expectedHolderDID: "did:key:unused",
                at: Date(timeIntervalSince1970: 1_800_000_000)
            )
        }
        #expect(await transport.requestPaths.isEmpty)
    }

    @Test("Development policy permits a cryptographically valid delegated did:key issuer")
    func permitsDevelopmentDIDIssuerDelegation() async throws {
        let key = P256.Signing.PrivateKey()
        let signedIssuer = try KeyDIDResolver().derive(publicKeyX963: key.publicKey.x963Representation)
        let document = try await KeyDIDResolver().resolve(signedIssuer)
        let kid = try #require(document.assertionMethod.first)
        let credential = try signedSDJWT(key: key, kid: kid, issuer: signedIssuer)
        let validator = NativeW3CCredentialValidator(
            resolver: KeyDIDResolver(),
            allowsDIDIssuerDelegation: true
        )

        let result = try await validator.validate(
            rawCredential: Data(credential.utf8),
            profile: .dcSdJWTVC(),
            expectedIssuer: "https://issuer.dev.oari.io/authority-server/openid",
            expectedHolderDID: "did:key:unused",
            at: Date(timeIntervalSince1970: 1_800_000_000)
        )
        #expect(result == signedIssuer)

        let strict = NativeW3CCredentialValidator(resolver: KeyDIDResolver())
        await #expect(throws: EbsiCredentialError.issuerMismatch) {
            try await strict.validate(
                rawCredential: Data(credential.utf8),
                profile: .dcSdJWTVC(),
                expectedIssuer: "https://issuer.dev.oari.io/authority-server/openid",
                expectedHolderDID: "did:key:unused",
                at: Date(timeIntervalSince1970: 1_800_000_000)
            )
        }
    }

    @Test("Published key does not permit a forged SD-JWT")
    func rejectsForgedCredential() async throws {
        let publishedKey = P256.Signing.PrivateKey()
        let attackerKey = P256.Signing.PrivateKey()
        let transport = HTTPSIssuerFixtureTransport(issuer: issuer, publicKey: publishedKey.publicKey)
        let validator = NativeW3CCredentialValidator(
            resolver: RejectingDIDResolver(),
            transport: transport
        )
        let credential = try signedSDJWT(key: attackerKey, kid: "igrant-signing-key")

        await #expect(throws: EbsiCredentialError.invalidSignature) {
            try await validator.validate(
                rawCredential: Data(credential.utf8),
                profile: .dcSdJWTVC(),
                expectedIssuer: issuer,
                expectedHolderDID: "did:key:unused",
                at: Date(timeIntervalSince1970: 1_800_000_000)
            )
        }
    }

    private func signedSDJWT(
        key: P256.Signing.PrivateKey,
        kid: String,
        issuer: String? = nil
    ) throws -> String {
        let header = try encoded(["alg": "ES256", "kid": kid, "typ": "dc+sd-jwt"])
        let payload = try encoded(["iss": issuer ?? self.issuer, "vct": "QESAC"])
        let input = Data("\(header).\(payload)".utf8)
        let signature = try key.signature(for: input).rawRepresentation
        return "\(header).\(payload).\(base64URL(signature))~"
    }

    private func encoded(_ value: [String: String]) throws -> String {
        base64URL(try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]))
    }

    private func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private struct RejectingDIDResolver: DIDResolver {
    func resolve(_ did: String) async throws -> DIDDocument {
        throw DIDResolutionError.unsupportedMethod
    }
}

private actor HTTPSIssuerFixtureTransport: OpenID4VCHTTPTransport {
    private let issuer: String
    private let metadataIssuer: String
    private let jwtVCMetadataIssuer: String
    private let includesMetadataIssuer: Bool
    private let publicKey: P256.Signing.PublicKey
    private(set) var requestPaths: [String] = []

    init(
        issuer: String,
        publicKey: P256.Signing.PublicKey,
        metadataIssuer: String? = nil,
        jwtVCMetadataIssuer: String = "https://oid4vc.igrant.io/organisation/test/service",
        includesMetadataIssuer: Bool = true
    ) {
        self.issuer = issuer
        self.metadataIssuer = metadataIssuer ?? issuer
        self.jwtVCMetadataIssuer = jwtVCMetadataIssuer
        self.includesMetadataIssuer = includesMetadataIssuer
        self.publicKey = publicKey
    }

    func send(
        url: URL,
        method: String,
        headers: [String: String],
        body: Data?
    ) async throws -> OpenID4VCHTTPResponse {
        requestPaths.append(url.path)
        if url.path.hasPrefix("/.well-known/jwt-vc-issuer/") {
            var metadata = [
                "jwks_uri": "https://oid4vc.igrant.io/organisation/test/service/jwks",
            ]
            if includesMetadataIssuer { metadata["issuer"] = jwtVCMetadataIssuer }
            return try response(metadata)
        }
        if url.path.hasPrefix("/.well-known/oauth-authorization-server/") {
            var metadata = [
                "jwks_uri": "https://oid4vc.igrant.io/organisation/test/service/jwks",
            ]
            if includesMetadataIssuer { metadata["issuer"] = metadataIssuer }
            return try response(metadata)
        }
        if url.path.hasSuffix("/.well-known/openid-configuration") {
            var metadata = [
                "jwks_uri": "https://oid4vc.igrant.io/organisation/test/service/jwks",
            ]
            if includesMetadataIssuer { metadata["issuer"] = metadataIssuer }
            return try response(metadata)
        }
        if url.path.hasSuffix("/service/jwks") {
            let bytes = publicKey.x963Representation
            return try response([
                "keys": [[
                    "kid": "igrant-signing-key",
                    "kty": "EC",
                    "crv": "P-256",
                    "use": "sig",
                    "alg": "ES256",
                    "x": base64URL(bytes.subdata(in: 1..<33)),
                    "y": base64URL(bytes.subdata(in: 33..<65)),
                ]],
            ])
        }
        return OpenID4VCHTTPResponse(statusCode: 404, body: Data())
    }

    private func response(_ object: Any) throws -> OpenID4VCHTTPResponse {
        OpenID4VCHTTPResponse(
            statusCode: 200,
            body: try JSONSerialization.data(withJSONObject: object),
            headers: ["Content-Type": "application/json"]
        )
    }

    private func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
