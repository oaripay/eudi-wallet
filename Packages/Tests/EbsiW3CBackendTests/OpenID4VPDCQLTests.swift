import EbsiW3CBackend
import Testing

struct OpenID4VPDCQLTests {
    @Test("Claims may be absent and extensions are ignored")
    func parsesAbsentClaimsAndExtensions() throws {
        let query = try OpenID4VPDCQLQuery.parse([
            "credentials": .array([.object([
                "id": .string("pid_1"), "format": .string("dc+sd-jwt"), "meta": .object([:]),
                "future_extension": .bool(true),
            ])]),
            "future_query_extension": .string("ignored"),
        ])
        #expect(query.credentials[0].claims.isEmpty)
    }

    @Test("Integer and null path components have canonical distinct identities")
    func parsesTypedPathComponentsWithoutCollisions() throws {
        let query = try OpenID4VPDCQLQuery.parse(baseCredential(claims: [
            ["path": .array([.string("items"), .number(0), .null])],
            ["path": .array([.string("items"), .string("0"), .string("*")])],
        ]))
        let claims = query.credentials[0].claims
        #expect(claims[0].path == [.string("items"), .index(0), .wildcard])
        #expect(claims[0].id != claims[1].id)
        #expect(claims[0].id.contains("/i:0/w:"))
    }

    @Test("Generated claim identity is distinct from the optional wire DCQL ID")
    func preservesExplicitDCQLIDSeparately() throws {
        let query = try OpenID4VPDCQLQuery.parse(baseCredential(claims: [
            ["id": .string("given_name"), "path": .array([.string("given_name")])],
        ]))
        let claim = try #require(query.credentials[0].claims.first)
        #expect(claim.dcqlID == "given_name")
        #expect(claim.id != claim.dcqlID)
    }

    @Test("Duplicate and malformed identifiers are rejected")
    func rejectsDuplicateAndMalformedIDs() throws {
        #expect(throws: OpenID4VPDCQLError.duplicateCredentialID("pid")) {
            _ = try OpenID4VPDCQLQuery.parse([
                "credentials": .array([.object(credential("pid")), .object(credential("pid"))]),
            ])
        }
        await #expect(throws: OpenID4VPDCQLError.invalidID(value: "bad id", context: "credential 0")) {
            _ = try OpenID4VPDCQLQuery.parse(["credentials": .array([.object(credential("bad id"))])])
        }
    }

    @Test("Malformed fields and set evaluation are typed errors")
    func rejectsMalformedAndDefersSetEvaluation() throws {
        #expect(throws: OpenID4VPDCQLError.invalidMeta(credentialID: "pid")) {
            _ = try OpenID4VPDCQLQuery.parse(["credentials": .array([.object([
                "id": .string("pid"), "format": .string("dc+sd-jwt"), "meta": .string("bad"),
            ])])])
        }
        let query = try OpenID4VPDCQLQuery.parse([
            "credentials": .array([.object(credential("pid"))]),
            "credential_sets": .array([.object(["options": .array([.array([.string("pid")])])])]),
        ])
        #expect(throws: OpenID4VPDCQLError.unsupportedCredentialSetEvaluation) {
            try query.requireCurrentlySupportedEvaluation()
        }
    }

    @Test("Unsupported query cardinality, multiple, and claim sets remain typed capabilities")
    func reportsUnsupportedCapabilities() throws {
        let multipleQueries = try OpenID4VPDCQLQuery.parse([
            "credentials": .array([.object(credential("pid")), .object(credential("pid2"))]),
        ])
        #expect(throws: OpenID4VPDCQLError.unsupportedMultipleCredentialQueries) {
            try multipleQueries.requireCurrentlySupportedEvaluation()
        }

        var multiple = credential("pid")
        multiple["multiple"] = .bool(true)
        let multiplePresentations = try OpenID4VPDCQLQuery.parse([
            "credentials": .array([.object(multiple)]),
        ])
        #expect(throws: OpenID4VPDCQLError.unsupportedMultipleCredentialPresentation) {
            try multiplePresentations.requireCurrentlySupportedEvaluation()
        }

        var claimSets = credential("pid")
        claimSets["claims"] = .array([.object(["id": .string("name"), "path": .array([.string("name")])])])
        claimSets["claim_sets"] = .array([.array([.string("name")])])
        let alternatives = try OpenID4VPDCQLQuery.parse([
            "credentials": .array([.object(claimSets)]),
        ])
        #expect(throws: OpenID4VPDCQLError.unsupportedClaimSetEvaluation) {
            try alternatives.requireCurrentlySupportedEvaluation()
        }
    }

    private func baseCredential(claims: [[String: AnySendableJSON]]) -> [String: AnySendableJSON] {
        var value = credential("pid")
        value["claims"] = .array(claims.map(AnySendableJSON.object))
        return ["credentials": .array([.object(value)])]
    }

    private func credential(_ id: String) -> [String: AnySendableJSON] {
        ["id": .string(id), "format": .string("dc+sd-jwt"), "meta": .object([:])]
    }
}
