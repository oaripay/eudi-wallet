import Foundation

public struct CredentialOfferParser: Sendable {
    public init() {}

    public func parse(json: Data) throws -> CredentialOffer {
        let object: [String: Any]
        do {
            guard let decoded = try JSONSerialization.jsonObject(with: json) as? [String: Any] else {
                throw IssuanceError.malformedJSON
            }
            object = decoded
        } catch let error as IssuanceError {
            throw error
        } catch {
            throw IssuanceError.malformedJSON
        }
        guard let issuerString = object["credential_issuer"] as? String,
              let issuer = URL(string: issuerString), issuer.isCanonicalHTTPS else {
            throw IssuanceError.invalidURL
        }
        guard let configurations = object["credential_configuration_ids"] as? [String],
              !configurations.isEmpty else {
            throw IssuanceError.missingField("credential_configuration_ids")
        }
        guard let grants = object["grants"] as? [String: Any] else {
            throw IssuanceError.missingField("grants")
        }
        if let authorization = grants["authorization_code"] as? [String: Any] {
            guard let serverString = authorization["authorization_server"] as? String,
                  let server = URL(string: serverString), server.isCanonicalHTTPS else {
                throw IssuanceError.invalidURL
            }
            return CredentialOffer(
                credentialIssuer: issuer,
                configurationIDs: configurations,
                grant: .authorizationCode(authorizationServer: server)
            )
        }
        if let preAuthorized = grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"] as? [String: Any] {
            guard let code = preAuthorized["pre-authorized_code"] as? String,
                  !code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw IssuanceError.missingField("pre-authorized_code")
            }
            return CredentialOffer(
                credentialIssuer: issuer,
                configurationIDs: configurations,
                grant: .preAuthorizedCode(
                    code: code,
                    txCodeRequired: preAuthorized["tx_code"] != nil
                )
            )
        }
        throw IssuanceError.unsupportedGrant
    }
}

extension URL {
    var isCanonicalHTTPS: Bool {
        normalizedOrigin != nil && user == nil && password == nil
    }
}
