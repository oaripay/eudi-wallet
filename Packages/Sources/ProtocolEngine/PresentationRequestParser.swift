import Foundation
import ProfileDomain

public struct PresentationRequest: Equatable, Sendable {
    public let id: String
    public let clientID: String
    public let responseURI: URL
    public let nonce: String
    public let expiresAt: Date
    public let state: String?
    public let presentationDefinitionID: String?
    public let dcqlCredentialIDs: [String]
    public let profileID: ProfileID

    public init(
        id: String,
        clientID: String,
        responseURI: URL,
        nonce: String,
        expiresAt: Date,
        state: String?,
        presentationDefinitionID: String?,
        dcqlCredentialIDs: [String],
        profileID: ProfileID
    ) {
        self.id = id
        self.clientID = clientID
        self.responseURI = responseURI
        self.nonce = nonce
        self.expiresAt = expiresAt
        self.state = state
        self.presentationDefinitionID = presentationDefinitionID
        self.dcqlCredentialIDs = dcqlCredentialIDs
        self.profileID = profileID
    }
}

public enum PresentationRequestError: Error, Equatable, Sendable {
    case malformedJSON
    case missingField(String)
    case invalidURI
    case missingQuery
    case unsupportedQuery
}

public struct PresentationRequestParser: Sendable {
    public init() {}

    public func parse(
        json: Data,
        profileID: ProfileID,
        expectedResponseOrigin: URL
    ) throws -> PresentationRequest {
        let object: [String: Any]
        do {
            guard let decoded = try JSONSerialization.jsonObject(with: json) as? [String: Any] else {
                throw PresentationRequestError.malformedJSON
            }
            object = decoded
        } catch let error as PresentationRequestError {
            throw error
        } catch {
            throw PresentationRequestError.malformedJSON
        }

        let id = try string("id", in: object)
        let clientID = try string("client_id", in: object)
        let responseURI = try url("response_uri", in: object)
        let nonce = try string("nonce", in: object)
        if nonce.count < 16 { throw PresentationRequestError.missingField("nonce") }
        guard let clientOrigin = URL(string: clientID),
              responseURI.normalizedOrigin == expectedResponseOrigin.normalizedOrigin,
              clientOrigin.normalizedOrigin == expectedResponseOrigin.normalizedOrigin else {
            throw PresentationRequestError.invalidURI
        }
        guard let expiration = object["exp"] as? TimeInterval else {
            throw PresentationRequestError.missingField("exp")
        }
        let state = object["state"] as? String
        let definitionID = object["presentation_definition_id"] as? String
        let dcqlIDs = ((object["dcql_query"] as? [String: Any])?["credentials"] as? [[String: Any]] ?? [])
            .compactMap { $0["id"] as? String }
        guard definitionID != nil || !dcqlIDs.isEmpty else {
            throw PresentationRequestError.missingQuery
        }
        return PresentationRequest(
            id: id,
            clientID: clientID,
            responseURI: responseURI,
            nonce: nonce,
            expiresAt: Date(timeIntervalSince1970: expiration),
            state: state,
            presentationDefinitionID: definitionID,
            dcqlCredentialIDs: dcqlIDs,
            profileID: profileID
        )
    }

    private func string(_ key: String, in object: [String: Any]) throws -> String {
        guard let value = object[key] as? String, !value.isEmpty else {
            throw PresentationRequestError.missingField(key)
        }
        return value
    }

    private func url(_ key: String, in object: [String: Any]) throws -> URL {
        guard let value = object[key] as? String, let url = URL(string: value),
              url.scheme?.lowercased() == "https", url.host != nil else {
            throw PresentationRequestError.invalidURI
        }
        return url
    }
}

extension URL {
    var normalizedOrigin: String? {
        guard scheme?.lowercased() == "https", let host = host?.lowercased(), !host.isEmpty else {
            return nil
        }
        let effectivePort = port ?? 443
        return "https://\(host):\(effectivePort)"
    }
}
