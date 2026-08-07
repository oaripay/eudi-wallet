import Foundation
import LocalAuthentication
import ProtocolEngine

public struct SystemLocalAuthenticator: LocalAuthenticator, Sendable {
    private let evaluate: @Sendable (String) async throws -> Bool

    public init() {
        evaluate = { reason in
            let context = LAContext()
            context.localizedCancelTitle = "Cancel"
            var authorizationError: NSError?
            guard context.canEvaluatePolicy(
                .deviceOwnerAuthentication,
                error: &authorizationError
            ) else {
                throw LocalAuthenticationError.unavailable(
                    authorizationError?.code ?? LAError.biometryNotAvailable.rawValue
                )
            }
            do {
                return try await context.evaluatePolicy(
                    .deviceOwnerAuthentication,
                    localizedReason: reason
                )
            } catch let error as LAError {
                throw LocalAuthenticationError.failed(error.code.rawValue)
            }
        }
    }

    init(
        evaluator: @escaping @Sendable (String) async throws -> Bool
    ) {
        evaluate = evaluator
    }

    public func authenticate(reason: String) async throws {
        let reason = reason.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !reason.isEmpty else {
            throw LocalAuthenticationError.missingReason
        }
        guard try await evaluate(reason) else {
            throw LocalAuthenticationError.denied
        }
    }
}

public enum LocalAuthenticationError: Error, Equatable, Sendable {
    case missingReason
    case unavailable(Int)
    case failed(Int)
    case denied
}
