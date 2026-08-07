import SwiftUI

public struct OariCard<Content: View>: View {
    @Environment(\.colorScheme) private var scheme
    private let content: Content

    public init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    public var body: some View {
        content
            .padding(OariSpacing.x5)
            .background(OariColor.surface(scheme))
            .clipShape(RoundedRectangle(cornerRadius: OariRadius.extraLarge))
            .overlay {
                RoundedRectangle(cornerRadius: OariRadius.extraLarge)
                    .stroke(OariColor.border(scheme))
            }
    }
}

public enum OariStatusKind: Sendable {
    case trusted
    case warning
    case invalid
    case indeterminate

    var icon: String {
        switch self {
        case .trusted: "checkmark.shield.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .invalid: "xmark.octagon.fill"
        case .indeterminate: "questionmark.diamond.fill"
        }
    }
}

public struct OariStatusBadge: View {
    @Environment(\.colorScheme) private var scheme
    private let label: String
    private let kind: OariStatusKind

    public init(_ label: String, kind: OariStatusKind) {
        self.label = label
        self.kind = kind
    }

    public var body: some View {
        Label(label, systemImage: kind.icon)
            .font(OariTypography.label)
            .foregroundStyle(kind == .trusted ? OariColor.success : OariColor.textPrimary(scheme))
            .padding(.horizontal, OariSpacing.x3)
            .padding(.vertical, OariSpacing.x2)
            .background(OariColor.surfaceInset(scheme), in: Capsule())
            .accessibilityLabel("Trust status: \(label)")
    }
}

public struct OariPrimaryButtonStyle: ButtonStyle {
    public init() {}

    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(OariTypography.action)
            .foregroundStyle(OariColor.textOnAction)
            .frame(maxWidth: .infinity)
            .padding(.vertical, OariSpacing.x4)
            .background(OariColor.action.opacity(configuration.isPressed ? 0.78 : 1))
            .clipShape(Capsule())
    }
}
