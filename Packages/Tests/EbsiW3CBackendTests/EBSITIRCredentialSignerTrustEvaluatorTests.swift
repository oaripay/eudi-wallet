import CryptoKit
import EbsiW3CBackend
import Foundation
import IdentityDomain
import Testing
import TrustDomain

struct EBSITIRCredentialSignerTrustEvaluatorTests {
    private let issuer = "did:ebsi:zIssuer123"
    private let base = URL(string: "https://ebsi.oari.io/trusted-issuers-registry/v5/issuers")!
    private let date = Date(timeIntervalSince1970: 1_800_000_000)

    @Test("A registry attribute is trusted only after VCDM 1.1 JWT verification")
    func validatesAccreditationJWTWithoutFollowingHTTPLinks() async throws {
        let key = P256.Signing.PrivateKey()
        let jwt = try accreditationJWT(key: key, expiration: date.addingTimeInterval(600))
        let transport = TIRMockTransport(responses: responses(attributeBody: jwt))
        let evaluator = EBSITIRCredentialSignerTrustEvaluator(
            tirBaseURL: base,
            transport: transport,
            resolver: TIRMockResolver(document: didDocument(for: key))
        )

        let verdict = await evaluator.evaluate(issuer: issuer, at: date)
        guard case let .trusted(evidence) = verdict else {
            Issue.record("Expected cryptographically verified TIR evidence")
            return
        }
        #expect(evidence.first?.result == .valid)
        let requested = await transport.requestedURLs
        #expect(requested.count == 3)
        #expect(requested.allSatisfy { $0.scheme == "https" })
        #expect(requested.last?.path.hasSuffix("/attributes/attribute-1") == true)
    }

    @Test("A VCDM2 top-level vc+jwt accreditation is validated independently")
    func validatesVCDM2Accreditation() async throws {
        let key = P256.Signing.PrivateKey()
        let jwt = try vcdm2AccreditationJWT(key: key, expiration: date.addingTimeInterval(600))
        let evaluator = EBSITIRCredentialSignerTrustEvaluator(
            tirBaseURL: base,
            transport: TIRMockTransport(responses: responses(attributeBody: jwt)),
            resolver: TIRMockResolver(document: didDocument(for: key))
        )
        guard case .trusted = await evaluator.evaluate(issuer: issuer, at: date) else {
            Issue.record("Expected a strict VCDM2 accreditation to establish trust")
            return
        }
    }

    @Test("HTTP 200, expired signatures, and explicit allowlist misses fail closed")
    func rejectsInsufficientEvidence() async throws {
        let key = P256.Signing.PrivateKey()
        let expired = try accreditationJWT(key: key, expiration: date.addingTimeInterval(-1))
        let transport = TIRMockTransport(responses: responses(attributeBody: expired))
        let resolver = TIRMockResolver(document: didDocument(for: key))
        let evaluator = EBSITIRCredentialSignerTrustEvaluator(
            tirBaseURL: base, transport: transport, resolver: resolver
        )
        guard case .invalid = await evaluator.evaluate(issuer: issuer, at: date) else {
            Issue.record("An expired attribute must not be trusted")
            return
        }

        let restricted = EBSITIRCredentialSignerTrustEvaluator(
            tirBaseURL: base,
            transport: transport,
            resolver: resolver,
            approvedIssuerDIDs: []
        )
        guard case .untrusted = await restricted.evaluate(issuer: issuer, at: date) else {
            Issue.record("An explicitly empty allowlist must deny all issuers")
            return
        }

        let expiredCredential = try accreditationJWT(
            key: key,
            expiration: date.addingTimeInterval(600),
            credentialExpiration: date.addingTimeInterval(-1)
        )
        let expiredCredentialEvaluator = EBSITIRCredentialSignerTrustEvaluator(
            tirBaseURL: base,
            transport: TIRMockTransport(responses: responses(attributeBody: expiredCredential)),
            resolver: resolver
        )
        guard case .invalid = await expiredCredentialEvaluator.evaluate(issuer: issuer, at: date) else {
            Issue.record("An expired VCDM 1.1 accreditation must not be trusted")
            return
        }

        let wrongType = try accreditationJWT(
            key: key,
            expiration: date.addingTimeInterval(600),
            types: ["VerifiableCredential"]
        )
        let wrongTypeEvaluator = EBSITIRCredentialSignerTrustEvaluator(
            tirBaseURL: base,
            transport: TIRMockTransport(responses: responses(attributeBody: wrongType)),
            resolver: resolver
        )
        guard case .invalid = await wrongTypeEvaluator.evaluate(issuer: issuer, at: date) else {
            Issue.record("A non-accreditation VC must not establish TIR trust")
            return
        }
    }

    private func responses(attributeBody: String) -> [String: OpenID4VCHTTPResponse] {
        let issuerURL = base.appendingPathComponent(issuer).absoluteString
        let attributesURL = base.appendingPathComponent(issuer).appendingPathComponent("attributes")
        return [
            issuerURL: jsonResponse([
                "did": issuer,
                "hasAttributes": true,
                "attributes": "http://attacker.example/attributes",
            ]),
            attributesURL.absoluteString: jsonResponse([
                "items": [["id": "attribute-1", "href": "http://attacker.example/attribute.jwt"]],
            ]),
            attributesURL.appendingPathComponent("attribute-1").absoluteString: jsonResponse([
                "did": issuer,
                "attribute": ["body": attributeBody],
            ]),
        ]
    }

    private func jsonResponse(_ object: Any) -> OpenID4VCHTTPResponse {
        OpenID4VCHTTPResponse(statusCode: 200, body: try! JSONSerialization.data(withJSONObject: object))
    }

    private func accreditationJWT(
        key: P256.Signing.PrivateKey,
        expiration: Date,
        credentialExpiration: Date? = nil,
        types: [String] = ["VerifiableCredential", "VerifiableAccreditation"]
    ) throws -> String {
        let credentialExpiration = credentialExpiration ?? expiration
        let issuance = date.addingTimeInterval(-60)
        let keyID = "\(issuer)#key-1"
        let header = try JSONSerialization.data(withJSONObject: ["alg": "ES256", "kid": keyID, "typ": "JWT"])
        let payload = try JSONSerialization.data(withJSONObject: [
            "iss": issuer,
            "sub": issuer,
            "iat": date.timeIntervalSince1970 - 60,
            "nbf": date.timeIntervalSince1970 - 60,
            "exp": expiration.timeIntervalSince1970,
            "vc": [
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": types,
                "issuer": issuer,
                "credentialSubject": ["id": issuer],
                "issuanceDate": ISO8601DateFormatter().string(from: issuance),
                "expirationDate": ISO8601DateFormatter().string(from: credentialExpiration),
            ],
        ])
        let input = "\(base64URL(header)).\(base64URL(payload))"
        let signature = try key.signature(for: Data(input.utf8)).rawRepresentation
        return "\(input).\(base64URL(signature))"
    }

    private func vcdm2AccreditationJWT(
        key: P256.Signing.PrivateKey,
        expiration: Date
    ) throws -> String {
        let issuance = date.addingTimeInterval(-60)
        let keyID = "\(issuer)#key-1"
        let header = try JSONSerialization.data(withJSONObject: ["alg": "ES256", "kid": keyID, "typ": "vc+jwt"])
        let payload = try JSONSerialization.data(withJSONObject: [
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "VerifiableAccreditation"],
            "issuer": issuer,
            "credentialSubject": ["id": issuer],
            "validFrom": ISO8601DateFormatter().string(from: issuance),
            "validUntil": ISO8601DateFormatter().string(from: expiration),
            "iss": issuer,
            "sub": issuer,
            "nbf": issuance.timeIntervalSince1970,
            "exp": expiration.timeIntervalSince1970,
        ])
        let input = "\(base64URL(header)).\(base64URL(payload))"
        let signature = try key.signature(for: Data(input.utf8)).rawRepresentation
        return "\(input).\(base64URL(signature))"
    }

    private func didDocument(for key: P256.Signing.PrivateKey) -> DIDDocument {
        let bytes = key.publicKey.x963Representation
        let keyID = "\(issuer)#key-1"
        return DIDDocument(
            id: issuer,
            verificationMethod: [DIDVerificationMethod(
                id: keyID,
                type: "JsonWebKey2020",
                controller: issuer,
                publicKeyJwk: PublicJWK(
                    kty: "EC", crv: "P-256",
                    x: base64URL(Data(bytes[1...32])),
                    y: base64URL(Data(bytes[33...64]))
                )
            )],
            authentication: [],
            assertionMethod: [keyID]
        )
    }

    private func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private actor TIRMockTransport: OpenID4VCHTTPTransport {
    let responses: [String: OpenID4VCHTTPResponse]
    private(set) var requestedURLs: [URL] = []

    init(responses: [String: OpenID4VCHTTPResponse]) { self.responses = responses }

    func send(
        url: URL, method: String, headers: [String: String], body: Data?
    ) async throws -> OpenID4VCHTTPResponse {
        requestedURLs.append(url)
        guard let response = responses[url.absoluteString] else { throw TIRMockError.missingResponse }
        return response
    }
}

private struct TIRMockResolver: DIDResolver {
    let document: DIDDocument
    func resolve(_ did: String) async throws -> DIDDocument {
        guard did == document.id else { throw DIDResolutionError.notFound }
        return document
    }
}

private enum TIRMockError: Error { case missingResponse }
