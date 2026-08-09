import Foundation
import ProfileDomain
import ProtocolEngine
import Testing

struct VPProtocolEngineTests {
    @Test("Input classifier routes VP and rejects oversized or unsupported input")
    func inputClassification() throws {
        let classifier = ProtocolInputClassifier(allowedHosts: ["verifier.example"])
        guard case .openID4VP = try classifier.classify(
            "https://verifier.example/present?request_uri=https://verifier.example/request.jwt"
        ) else {
            Issue.record("Expected VP route")
            return
        }
        #expect(throws: ProtocolInputError.tooLarge) {
            try ProtocolInputClassifier(maximumBytes: 4, allowedHosts: ["a.example"]).classify("https://a.example")
        }
        #expect(throws: ProtocolInputError.unsupportedScheme) {
            try classifier.classify("file:///tmp/request")
        }
        #expect(throws: ProtocolInputError.unsupportedHost) {
            try classifier.classify("https://evil.example/present?request=x")
        }
        #expect(throws: ProtocolInputError.missingHostConfiguration) {
            try ProtocolInputClassifier(allowedHosts: []).classify(
                "https://verifier.example/present?request=x"
            )
        }
        #expect(throws: ProtocolInputError.unsupportedHost) {
            try classifier.classify("https:present?request=x")
        }
    }

    @Test("VP request parser requires HTTPS response, nonce, and query")
    func requestParsing() throws {
        let data = Data("""
        {"id":"req-1","client_id":"https://verifier.example","response_uri":"https://verifier.example/cb","nonce":"1234567890123456","exp":1754524860,"state":"state-1","dcql_query":{"credentials":[{"id":"pid"}]}}
        """.utf8)
        let parsed = try PresentationRequestParser().parse(
            json: data,
            profileID: BuiltInProfiles.vcdm2OpenID4VCProfileID,
            expectedResponseOrigin: URL(string: "https://verifier.example")!
        )
        #expect(parsed.id == "req-1")
        #expect(parsed.dcqlCredentialIDs == ["pid"])

        let noQuery = Data("{\"id\":\"x\",\"client_id\":\"https://verifier.example\",\"response_uri\":\"https://verifier.example/cb\",\"nonce\":\"1234567890123456\",\"exp\":1754524860}".utf8)
        #expect(throws: PresentationRequestError.missingQuery) {
            try PresentationRequestParser().parse(
                json: noQuery,
                profileID: BuiltInProfiles.vcdm2OpenID4VCProfileID,
                expectedResponseOrigin: URL(string: "https://verifier.example")!
            )
        }
        #expect(throws: PresentationRequestError.invalidURI) {
            try PresentationRequestParser().parse(
                json: data,
                profileID: BuiltInProfiles.vcdm2OpenID4VCProfileID,
                expectedResponseOrigin: URL(string: "https://verifier.example:8443")!
            )
        }
    }

    @Test("Nonce can only be claimed once and expired nonces fail")
    func nonceReplay() async throws {
        let store = ReplayProtectionStore()
        let now = Date(timeIntervalSince1970: 1_754_524_800)
        try await store.claim(nonce: "nonce-1", expiresAt: now.addingTimeInterval(60), now: now)
        await #expect(throws: ReplayError.replayed) {
            try await store.claim(nonce: "nonce-1", expiresAt: now.addingTimeInterval(60), now: now)
        }
        await #expect(throws: ReplayError.expired) {
            try await store.claim(nonce: "nonce-2", expiresAt: now, now: now)
        }
    }

    @Test("VP intake binds origin and claims nonce before returning request")
    func intakeReplay() async throws {
        let now = Date(timeIntervalSince1970: 1_754_524_800)
        let data = Data("""
        {"id":"req-1","client_id":"https://verifier.example","response_uri":"https://verifier.example/cb","nonce":"1234567890123456","exp":1754524860,"presentation_definition_id":"definition"}
        """.utf8)
        let intake = PresentationIntakeCoordinator(replay: ReplayProtectionStore())
        _ = try await intake.accept(
            json: data,
            profileID: BuiltInProfiles.vcdm2OpenID4VCProfileID,
            registeredOrigin: URL(string: "https://verifier.example")!,
            now: now
        )
        await #expect(throws: ReplayError.replayed) {
            try await intake.accept(
                json: data,
                profileID: BuiltInProfiles.vcdm2OpenID4VCProfileID,
                registeredOrigin: URL(string: "https://verifier.example")!,
                now: now
            )
        }
    }
}
