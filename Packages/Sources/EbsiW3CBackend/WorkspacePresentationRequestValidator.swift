import Foundation
import IdentityDomain

public struct VerifiedWorkspacePresentationRequest: Equatable, Sendable {
    public let clientID: String
    public let responseMode: String
    public let responseURI: String?
    public let nonce: String
    public let state: String?
    public let dcqlQuery: [String: AnySendableJSON]

    public init(
        clientID: String,
        responseMode: String,
        responseURI: String?,
        nonce: String,
        state: String?,
        dcqlQuery: [String: AnySendableJSON]
    ) {
        self.clientID = clientID
        self.responseMode = responseMode
        self.responseURI = responseURI
        self.nonce = nonce
        self.state = state
        self.dcqlQuery = dcqlQuery
    }
}

public protocol WorkspacePresentationRequestValidating: Sendable {
    func validate(compactJWT: String, at date: Date) async throws -> VerifiedWorkspacePresentationRequest
}

public struct NativeWorkspacePresentationRequestValidator: WorkspacePresentationRequestValidating {
    private let resolver: any DIDResolver

    public init(resolver: any DIDResolver) { self.resolver = resolver }

    public func validate(compactJWT: String, at date: Date) async throws -> VerifiedWorkspacePresentationRequest {
        let parts = compactJWT.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let headerData = Self.decodeBase64URL(String(parts[0])),
              let payloadData = Self.decodeBase64URL(String(parts[1])),
              let header = try? JSONDecoder().decode([String: AnySendableJSON].self, from: headerData),
              let payload = try? JSONDecoder().decode([String: AnySendableJSON].self, from: payloadData),
              header["typ"]?.string == "oauth-authz-req+jwt",
              let clientID = payload["client_id"]?.string,
              let responseMode = payload["response_mode"]?.string,
              let nonce = payload["nonce"]?.string,
              !nonce.isEmpty,
              let dcqlQuery = payload["dcql_query"]?.object,
              let kid = header["kid"]?.string,
              let did = Self.did(from: payload["iss"]?.string ?? kid) else {
            throw WorkspaceBackendError.invalidPresentationChallenge(reason: "signed request object was malformed")
        }
        let document: DIDDocument
        do {
            document = try await resolver.resolve(did)
        } catch {
            throw WorkspaceBackendError.invalidPresentationChallenge(reason: "signed request issuer DID could not be resolved")
        }
        let methods = try document.verificationMethod.map { method in
            guard method.publicKeyJwk.crv == "P-256", let y = method.publicKeyJwk.y else {
                throw WorkspaceBackendError.invalidPresentationChallenge(reason: "signed request used an unsupported key")
            }
            return EbsiVerificationMethod(
                id: method.id,
                controller: method.controller,
                key: .p256(
                    x: try Self.requiredBase64URL(method.publicKeyJwk.x),
                    y: try Self.requiredBase64URL(y)
                ),
                relationships: document.authentication.contains(method.id) ? [.authentication] : []
            )
        }
        let verified: VerifiedEbsiJWS
        do {
            verified = try EbsiJWSVerifier().verify(
                compactJWS: compactJWT,
                methods: methods,
                requirements: EbsiJWSRequirements(
                    allowedAlgorithms: [.es256],
                    requiredRelationship: .authentication,
                    expectedController: did,
                    expectedIssuer: payload["iss"]?.string,
                    validationDate: date
                )
            )
        } catch {
            throw WorkspaceBackendError.invalidPresentationChallenge(reason: "signed request signature was invalid")
        }
        guard verified.methodID == kid || kid.hasPrefix("\(did)#") else {
            throw WorkspaceBackendError.invalidPresentationChallenge(reason: "signed request kid was not bound to its issuer")
        }
        return VerifiedWorkspacePresentationRequest(
            clientID: clientID,
            responseMode: responseMode,
            responseURI: payload["response_uri"]?.string,
            nonce: nonce,
            state: payload["state"]?.string,
            dcqlQuery: dcqlQuery
        )
    }

    private static func did(from value: String) -> String? {
        guard value.hasPrefix("did:") else { return nil }
        return value.split(separator: "#", maxSplits: 1).first.map(String.init)
    }

    private static func requiredBase64URL(_ value: String) throws -> Data {
        guard let data = decodeBase64URL(value) else {
            throw WorkspaceBackendError.invalidPresentationChallenge(reason: "signed request key was malformed")
        }
        return data
    }

    private static func decodeBase64URL(_ value: String) -> Data? {
        var encoded = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        encoded += String(repeating: "=", count: (4 - encoded.count % 4) % 4)
        return Data(base64Encoded: encoded)
    }
}
