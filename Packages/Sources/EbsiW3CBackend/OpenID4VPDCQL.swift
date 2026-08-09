import Foundation

/// A typed representation of the DCQL portion of an OpenID4VP request.
///
/// The parser deliberately retains format-specific metadata and claim values as
/// `AnySendableJSON`, so callers that already receive decoded request objects
/// do not need to round-trip through `Data`.
public struct OpenID4VPDCQLQuery: Equatable, Sendable {
    public let credentials: [Credential]
    public let credentialSets: [CredentialSet]

    public init(credentials: [Credential], credentialSets: [CredentialSet] = []) {
        self.credentials = credentials
        self.credentialSets = credentialSets
    }

    public struct Credential: Equatable, Identifiable, Sendable {
        public let id: String
        public let format: String
        public let meta: [String: AnySendableJSON]
        public let claims: [Claim]
        public let claimSets: [ClaimSet]
        public let multiple: Bool?
        public let requireCryptographicHolderBinding: Bool?

        public init(
            id: String,
            format: String,
            meta: [String: AnySendableJSON],
            claims: [Claim] = [],
            claimSets: [ClaimSet] = [],
            multiple: Bool? = nil,
            requireCryptographicHolderBinding: Bool? = nil
        ) {
            self.id = id
            self.format = format
            self.meta = meta
            self.claims = claims
            self.claimSets = claimSets
            self.multiple = multiple
            self.requireCryptographicHolderBinding = requireCryptographicHolderBinding
        }
    }

    public struct Claim: Equatable, Identifiable, Sendable {
        /// Collision-safe generated identity for selection/UI use. It does not
        /// depend on the optional wire-level DCQL claim ID.
        public let id: String
        /// The explicit wire-level DCQL claim identifier, if one was supplied.
        public let dcqlID: String?
        public let path: [PathComponent]
        public let values: [AnySendableJSON]?

        public init(id: String, dcqlID: String?, path: [PathComponent], values: [AnySendableJSON]?) {
            self.id = id
            self.dcqlID = dcqlID
            self.path = path
            self.values = values
        }
    }

    public enum PathComponent: Equatable, Sendable {
        case string(String)
        case index(Int)
        case wildcard
    }

    /// A claim set means that one of its listed claim IDs may satisfy the
    /// request. It is parsed now but not evaluated by this backend yet.
    public struct ClaimSet: Equatable, Sendable {
        public let claimIDs: [String]
        public init(claimIDs: [String]) { self.claimIDs = claimIDs }
    }

    /// A credential set expresses alternatives between credential query IDs.
    /// It is parsed now but not evaluated by this backend yet.
    public struct CredentialSet: Equatable, Sendable {
        public let options: [[String]]
        public let required: Bool?
        public init(options: [[String]], required: Bool?) {
            self.options = options
            self.required = required
        }
    }

    /// Throws `unsupportedCredentialSetEvaluation` or
    /// `unsupportedClaimSetEvaluation` instead of silently applying incorrect
    /// set semantics. A future matching implementation can call this before
    /// evaluating a simple query.
    public func requireCurrentlySupportedEvaluation() throws {
        if credentials.count != 1 { throw OpenID4VPDCQLError.unsupportedMultipleCredentialQueries }
        if !credentialSets.isEmpty { throw OpenID4VPDCQLError.unsupportedCredentialSetEvaluation }
        if credentials.contains(where: { !$0.claimSets.isEmpty }) {
            throw OpenID4VPDCQLError.unsupportedClaimSetEvaluation
        }
        if credentials.contains(where: { $0.multiple == true }) {
            throw OpenID4VPDCQLError.unsupportedMultipleCredentialPresentation
        }
    }

    public static func parse(_ input: [String: AnySendableJSON]) throws -> Self {
        guard case let .array(rawCredentials)? = input["credentials"] else {
            throw OpenID4VPDCQLError.missingCredentials
        }
        guard !rawCredentials.isEmpty else { throw OpenID4VPDCQLError.emptyCredentials }
        var ids = Set<String>()
        let credentials = try rawCredentials.enumerated().map { index, raw in
            guard case let .object(object) = raw else {
                throw OpenID4VPDCQLError.invalidCredential(index: index)
            }
            return try parseCredential(object, index: index, ids: &ids)
        }
        let credentialSets = try parseCredentialSets(input["credential_sets"], knownCredentialIDs: ids)
        return Self(credentials: credentials, credentialSets: credentialSets)
    }

    /// A typed JSON Pointer-like representation. Type prefixes prevent a JSON
    /// string such as `"0"` or `"*"` from colliding with an array index or
    /// wildcard. JSON Pointer escaping keeps separators unambiguous.
    public static func canonicalPath(_ path: [PathComponent]) -> String {
        path.map { component in
            switch component {
            case let .string(value): return "/s:" + escapePointer(value)
            case let .index(value): return "/i:\(value)"
            case .wildcard: return "/w:"
            }
        }.joined()
    }

    private static func parseCredential(
        _ object: [String: AnySendableJSON], index: Int, ids: inout Set<String>
    ) throws -> Credential {
        guard let id = object["id"]?.string else { throw OpenID4VPDCQLError.missingCredentialID(index: index) }
        try validateID(id, context: "credential \(index)")
        guard ids.insert(id).inserted else { throw OpenID4VPDCQLError.duplicateCredentialID(id) }
        guard let format = object["format"]?.string, !format.isEmpty else {
            throw OpenID4VPDCQLError.invalidFormat(credentialID: id)
        }
        guard case let .object(meta)? = object["meta"] else {
            throw OpenID4VPDCQLError.invalidMeta(credentialID: id)
        }
        let claims = try parseClaims(object["claims"], credentialID: id)
        let claimSets = try parseClaimSets(object["claim_sets"], credentialID: id, claims: claims)
        let multiple = try optionalBool(object["multiple"], property: "multiple", credentialID: id)
        let binding = try optionalBool(
            object["require_cryptographic_holder_binding"],
            property: "require_cryptographic_holder_binding",
            credentialID: id
        )
        return Credential(id: id, format: format, meta: meta, claims: claims, claimSets: claimSets,
                          multiple: multiple, requireCryptographicHolderBinding: binding)
    }

    private static func parseClaims(_ raw: AnySendableJSON?, credentialID: String) throws -> [Claim] {
        guard let raw else { return [] }
        guard case let .array(items) = raw else { throw OpenID4VPDCQLError.invalidClaims(credentialID: credentialID) }
        var explicitIDs = Set<String>()
        return try items.enumerated().map { index, rawClaim in
            guard case let .object(object) = rawClaim,
                  case let .array(rawPath)? = object["path"], !rawPath.isEmpty else {
                throw OpenID4VPDCQLError.invalidClaim(credentialID: credentialID, index: index)
            }
            let dcqlID = object["id"]?.string
            if object["id"] != nil && dcqlID == nil { throw OpenID4VPDCQLError.invalidClaimID(credentialID: credentialID, index: index) }
            if let dcqlID {
                try validateID(dcqlID, context: "claim \(index) in credential \(credentialID)")
                guard explicitIDs.insert(dcqlID).inserted else {
                    throw OpenID4VPDCQLError.duplicateClaimID(credentialID: credentialID, id: dcqlID)
                }
            }
            let path = try rawPath.enumerated().map { pathIndex, value in
                switch value {
                case let .string(string): return PathComponent.string(string)
                case let .number(number) where number.isFinite && number >= 0 && number.rounded() == number && number <= Double(Int.max):
                    return PathComponent.index(Int(number))
                case .null: return PathComponent.wildcard
                default: throw OpenID4VPDCQLError.invalidPathComponent(credentialID: credentialID, claimIndex: index, pathIndex: pathIndex)
                }
            }
            let values: [AnySendableJSON]?
            if let rawValues = object["values"] {
                guard case let .array(array) = rawValues else {
                    throw OpenID4VPDCQLError.invalidValues(credentialID: credentialID, claimIndex: index)
                }
                values = array
            } else { values = nil }
            return Claim(id: "\(credentialID)#\(index):\(canonicalPath(path))", dcqlID: dcqlID,
                         path: path, values: values)
        }
    }

    private static func parseClaimSets(_ raw: AnySendableJSON?, credentialID: String, claims: [Claim]) throws -> [ClaimSet] {
        guard let raw else { return [] }
        guard case let .array(sets) = raw else { throw OpenID4VPDCQLError.invalidClaimSets(credentialID: credentialID) }
        let knownIDs = Set(claims.compactMap(\.dcqlID))
        return try sets.enumerated().map { setIndex, rawSet in
            guard case let .array(entries) = rawSet, !entries.isEmpty else {
                throw OpenID4VPDCQLError.invalidClaimSet(credentialID: credentialID, index: setIndex)
            }
            let claimIDs = entries.compactMap(\.string)
            guard claimIDs.count == entries.count, Set(claimIDs).count == claimIDs.count,
                  claimIDs.allSatisfy(knownIDs.contains) else {
                throw OpenID4VPDCQLError.invalidClaimSet(credentialID: credentialID, index: setIndex)
            }
            return ClaimSet(claimIDs: claimIDs)
        }
    }

    private static func parseCredentialSets(_ raw: AnySendableJSON?, knownCredentialIDs: Set<String>) throws -> [CredentialSet] {
        guard let raw else { return [] }
        guard case let .array(sets) = raw else { throw OpenID4VPDCQLError.invalidCredentialSets }
        return try sets.enumerated().map { index, rawSet in
            guard case let .object(object) = rawSet, case let .array(options)? = object["options"], !options.isEmpty else {
                throw OpenID4VPDCQLError.invalidCredentialSet(index: index)
            }
            let parsedOptions = try options.map { option -> [String] in
                guard case let .array(ids) = option, !ids.isEmpty else { throw OpenID4VPDCQLError.invalidCredentialSet(index: index) }
                let strings = ids.compactMap(\.string)
                guard strings.count == ids.count, Set(strings).count == strings.count,
                      strings.allSatisfy(knownCredentialIDs.contains) else { throw OpenID4VPDCQLError.invalidCredentialSet(index: index) }
                return strings
            }
            let required = try optionalBool(object["required"], property: "required", credentialID: "credential_set \(index)")
            return CredentialSet(options: parsedOptions, required: required)
        }
    }

    private static func optionalBool(_ value: AnySendableJSON?, property: String, credentialID: String) throws -> Bool? {
        guard let value else { return nil }
        guard case let .bool(bool) = value else { throw OpenID4VPDCQLError.invalidBoolean(property: property, context: credentialID) }
        return bool
    }

    private static func validateID(_ value: String, context: String) throws {
        guard !value.isEmpty, value.unicodeScalars.allSatisfy({
            ($0.value >= 65 && $0.value <= 90) || ($0.value >= 97 && $0.value <= 122) ||
            ($0.value >= 48 && $0.value <= 57) || $0.value == 95 || $0.value == 45
        }) else { throw OpenID4VPDCQLError.invalidID(value: value, context: context) }
    }

    private static func escapePointer(_ value: String) -> String {
        value.replacingOccurrences(of: "~", with: "~0").replacingOccurrences(of: "/", with: "~1")
    }
}

public enum OpenID4VPDCQLError: Error, Equatable, Sendable {
    case missingCredentials
    case emptyCredentials
    case invalidCredential(index: Int)
    case missingCredentialID(index: Int)
    case invalidID(value: String, context: String)
    case duplicateCredentialID(String)
    case invalidFormat(credentialID: String)
    case invalidMeta(credentialID: String)
    case invalidClaims(credentialID: String)
    case invalidClaim(credentialID: String, index: Int)
    case invalidClaimID(credentialID: String, index: Int)
    case duplicateClaimID(credentialID: String, id: String)
    case invalidPathComponent(credentialID: String, claimIndex: Int, pathIndex: Int)
    case invalidValues(credentialID: String, claimIndex: Int)
    case invalidBoolean(property: String, context: String)
    case invalidClaimSets(credentialID: String)
    case invalidClaimSet(credentialID: String, index: Int)
    case invalidCredentialSets
    case invalidCredentialSet(index: Int)
    case unsupportedCredentialSetEvaluation
    case unsupportedClaimSetEvaluation
    case unsupportedMultipleCredentialQueries
    case unsupportedMultipleCredentialPresentation
    case unsupportedClaimValueEvaluation
    case unsupportedPathStructure(claimIdentity: String)
}
