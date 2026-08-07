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
            .contentShape(Capsule())
            .frame(minHeight: OariControl.minimumHeight)
    }
}

public struct OariSecondaryButtonStyle: ButtonStyle {
    public init() {}
    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(OariTypography.action)
            .foregroundStyle(OariColor.action)
            .frame(maxWidth: .infinity, minHeight: OariControl.minimumHeight)
            .padding(.horizontal, OariControl.horizontalPadding)
            .background(OariColor.surfaceInset(.light).opacity(configuration.isPressed ? 0.65 : 1), in: Capsule())
            .overlay(Capsule().stroke(OariColor.action.opacity(0.4)))
    }
}

public struct OariDestructiveButtonStyle: ButtonStyle {
    public init() {}
    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(OariTypography.action)
            .foregroundStyle(.red)
            .frame(maxWidth: .infinity, minHeight: OariControl.minimumHeight)
            .padding(.horizontal, OariControl.horizontalPadding)
            .background(Color.red.opacity(configuration.isPressed ? 0.16 : 0.08), in: Capsule())
    }
}

public struct OariScreen<Content: View>: View {
    @Environment(\.colorScheme) private var scheme
    private let content: Content
    public init(@ViewBuilder content: () -> Content) { self.content = content() }
    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: OariSpacing.x5) { content }
                .padding(OariSpacing.x5)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(OariColor.background(scheme).ignoresSafeArea())
    }
}

public struct OariSectionHeader: View {
    private let title: String
    private let subtitle: String?
    public init(_ title: String, subtitle: String? = nil) {
        self.title = title; self.subtitle = subtitle
    }
    public var body: some View {
        VStack(alignment: .leading, spacing: OariSpacing.x1) {
            Text(title).font(OariTypography.section)
            if let subtitle { Text(subtitle).font(OariTypography.body).foregroundStyle(.secondary) }
        }
    }
}

public struct OariBackendBadge: View {
    private let text: String
    public init(_ text: String) { self.text = text }
    public var body: some View {
        Text(text)
            .font(OariTypography.label)
            .foregroundStyle(OariColor.action)
            .padding(.horizontal, OariSpacing.x2)
            .padding(.vertical, OariSpacing.x1)
            .background(OariColor.action.opacity(0.1), in: Capsule())
    }
}

public struct OariFlowFooter<Primary: View, Secondary: View>: View {
    private let primary: Primary
    private let secondary: Secondary
    public init(@ViewBuilder primary: () -> Primary, @ViewBuilder secondary: () -> Secondary) {
        self.primary = primary(); self.secondary = secondary()
    }
    public var body: some View {
        VStack(spacing: OariSpacing.x2) { primary; secondary }
            .padding(.top, OariSpacing.x3)
    }
}
