import Foundation
import ProfileDomain

public struct PresentationIntakeCoordinator: Sendable {
    private let parser: PresentationRequestParser
    private let replay: any ReplayProtection

    public init(
        parser: PresentationRequestParser = PresentationRequestParser(),
        replay: any ReplayProtection
    ) {
        self.parser = parser
        self.replay = replay
    }

    public func accept(
        json: Data,
        profileID: ProfileID,
        registeredOrigin: URL,
        now: Date
    ) async throws -> PresentationRequest {
        let request = try parser.parse(
            json: json,
            profileID: profileID,
            expectedResponseOrigin: registeredOrigin
        )
        try await replay.claim(nonce: request.nonce, expiresAt: request.expiresAt, now: now)
        return request
    }
}
