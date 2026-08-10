import Foundation
import ProtocolEngine
import Testing

struct IGrantDraftFixtureTests {
    @Test("iGrant Draft 13 offer stays in isolated adapter")
    func draft13Offer() throws {
        let data = try fixture("igrant-vci-draft13")
        let offer = try IGrantDraftCredentialOfferParser().parse(json: data)
        #expect(offer.configurationIDs == ["ExampleLegalPersonID"])
        guard case let .preAuthorizedCode(_, txCodeRequired) = offer.grant else {
            Issue.record("Expected pre-authorized grant")
            return
        }
        #expect(txCodeRequired)
    }

    @Test("iGrant Draft 18 presentation stays in isolated adapter")
    func draft18Presentation() throws {
        let data = try fixture("igrant-vp-draft18")
        let request = try IGrantDraftPresentationRequestParser().parse(
            json: data,
            expectedResponseOrigin: URL(string: "https://verifier.example")!
        )
        #expect(request.presentationDefinitionID == "igrant-presentation-definition")
        #expect(request.profileID.rawValue.contains("igrant"))
    }

    private func fixture(_ name: String) throws -> Data {
        let url = try #require(Bundle.module.url(forResource: name, withExtension: "json"))
        return try Data(contentsOf: url)
    }
}
