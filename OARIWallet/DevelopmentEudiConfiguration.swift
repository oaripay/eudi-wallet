import EudiWalletKitAdapter
import Foundation
import WalletDomain

struct DevelopmentEudiAttestationProvider: EudiWalletAttestationProviding {
    func walletAttestation(publicJWK: String) async throws -> String {
        token(type: "oauth-client-attestation+jwt", claims: ["cnf": ["jwk": try object(publicJWK)]])
    }

    func keyAttestation(publicJWKs: [String], nonce: String?) async throws -> String {
        var claims: [String: Any] = [
            "attested_keys": try publicJWKs.map(object),
            "iat": Int(Date().timeIntervalSince1970),
            "exp": Int(Date().addingTimeInterval(600).timeIntervalSince1970),
        ]
        if let nonce { claims["nonce"] = nonce }
        return token(type: "key-attestation+jwt", claims: claims)
    }

    private func object(_ value: String) throws -> [String: Any] {
        guard let object = try JSONSerialization.jsonObject(with: Data(value.utf8)) as? [String: Any] else {
            throw EudiWalletKitAdapterError.attestationEncodingFailed
        }
        return object
    }

    private func token(type: String, claims: [String: Any]) -> String {
        func encode(_ value: Any) -> String {
            (try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]))?
                .base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "") ?? ""
        }
        let signature = Data(repeating: 0, count: 64).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "\(encode(["alg": "ES256", "typ": type])).\(encode(claims)).\(signature)"
    }
}

struct DevelopmentEudiStatusProvider: EudiCredentialStatusProviding {
    func status(for document: EudiWalletDocumentSummary) async throws -> CredentialStatusState { .valid }
}

enum DevelopmentEudiProfile {
    static let trustAnchorDER: Data = {
        guard let url = Bundle.main.url(
            forResource: "DevelopmentTrustAnchor",
            withExtension: "der"
        ), let data = try? Data(contentsOf: url) else {
            preconditionFailure("Missing bundled development trust anchor")
        }
        return data
    }()
}
