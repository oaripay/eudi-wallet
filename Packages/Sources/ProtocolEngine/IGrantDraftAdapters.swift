import Foundation
import ProfileDomain

public struct IGrantDraftCredentialOfferParser: Sendable {
    public init() {}

    public func parse(json: Data) throws -> CredentialOffer {
        guard let object = try JSONSerialization.jsonObject(with: json) as? [String: Any],
              let issuerText = object["credential_issuer"] as? String,
              let issuer = URL(string: issuerText), issuer.isCanonicalHTTPS,
              let credentials = object["credentials"] as? [[String: Any]] else {
            throw IssuanceError.malformedJSON
        }
        let configurationIDs = credentials.compactMap {
            ($0["credential_configuration_id"] as? String)
                ?? ($0["types"] as? [String])?.last
        }
        guard !configurationIDs.isEmpty,
              let grants = object["grants"] as? [String: Any],
              let preAuthorized = grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"] as? [String: Any],
              let code = preAuthorized["pre-authorized_code"] as? String,
              !code.isEmpty else {
            throw IssuanceError.unsupportedGrant
        }
        return CredentialOffer(
            credentialIssuer: issuer,
            configurationIDs: configurationIDs,
            grant: .preAuthorizedCode(code: code, txCodeRequired: preAuthorized["tx_code"] != nil)
        )
    }
}

public struct IGrantDraftPresentationRequestParser: Sendable {
    public init() {}

    public func parse(
        json: Data,
        expectedResponseOrigin: URL
    ) throws -> PresentationRequest {
        guard var object = try JSONSerialization.jsonObject(with: json) as? [String: Any],
              let definition = object["presentation_definition"] as? [String: Any],
              let definitionID = definition["id"] as? String else {
            throw PresentationRequestError.missingQuery
        }
        object["presentation_definition_id"] = definitionID
        let normalized = try JSONSerialization.data(withJSONObject: object)
        return try PresentationRequestParser().parse(
            json: normalized,
            profileID: BuiltInProfiles.iGrantDraftCompatibilityID,
            expectedResponseOrigin: expectedResponseOrigin
        )
    }
}
