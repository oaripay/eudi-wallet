import Foundation
import LocalAuthentication
import ProtocolEngine

public enum DeviceAuthenticationKind: String, Equatable, Sendable {
    case faceID
    case touchID
    case devicePasscode
    case unavailable

    public var displayName: String {
        switch self {
        case .faceID: "Face ID"
        case .touchID: "Touch ID"
        case .devicePasscode: "Device Passcode"
        case .unavailable: "Device Authentication"
        }
    }
}

public protocol AppLockAuthenticating: Sendable {
    func availability() -> DeviceAuthenticationKind
    func authenticateAppLock(reason: String) async throws
}

public struct SystemLocalAuthenticator: LocalAuthenticator, AppLockAuthenticating, Sendable {
    private let evaluate: @Sendable (String) async throws -> Bool
    private let resolveAvailability: @Sendable () -> DeviceAuthenticationKind

    public init() {
        resolveAvailability = {
            let context = LAContext()
            var error: NSError?
            if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
                switch context.biometryType {
                case .faceID: return .faceID
                case .touchID: return .touchID
                default: break
                }
            }
            if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
                return .devicePasscode
            }
            return .unavailable
        }
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
        evaluator: @escaping @Sendable (String) async throws -> Bool,
        availability: @escaping @Sendable () -> DeviceAuthenticationKind = { .faceID }
    ) {
        evaluate = evaluator
        resolveAvailability = availability
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

    public func availability() -> DeviceAuthenticationKind { resolveAvailability() }

    public func authenticateAppLock(reason: String) async throws {
        try await authenticate(reason: reason)
    }
}

public enum LocalAuthenticationError: Error, Equatable, Sendable {
    case missingReason
    case unavailable(Int)
    case failed(Int)
    case denied
}
