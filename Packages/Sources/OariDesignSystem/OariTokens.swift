import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

public enum OariColor {
    public static let action = Color(red: 0, green: 157 / 255, blue: 1)
    public static let success = Color(red: 0, green: 220 / 255, blue: 185 / 255)
    public static let textOnAction = Color(red: 1, green: 1, blue: 1)

    public static func background(_ scheme: ColorScheme) -> Color {
        if scheme == .dark {
            return Color(red: 30 / 255, green: 30 / 255, blue: 30 / 255)
        }
#if canImport(UIKit)
        return Color(uiColor: .systemGroupedBackground)
#else
        return Color(red: 242 / 255, green: 242 / 255, blue: 247 / 255)
#endif
    }

    public static func surface(_ scheme: ColorScheme) -> Color {
        if scheme == .dark {
            return Color(red: 42 / 255, green: 42 / 255, blue: 42 / 255)
        }
#if canImport(UIKit)
        return Color(uiColor: .secondarySystemGroupedBackground)
#else
        return .white
#endif
    }

    public static func surfaceInset(_ scheme: ColorScheme) -> Color {
        scheme == .dark
            ? Color(red: 22 / 255, green: 22 / 255, blue: 22 / 255)
            : Color(red: 0, green: 43 / 255, blue: 77 / 255).opacity(0.03)
    }

    public static func textPrimary(_ scheme: ColorScheme) -> Color {
        scheme == .dark
            ? Color(red: 254 / 255, green: 254 / 255, blue: 254 / 255)
            : Color(red: 0, green: 43 / 255, blue: 77 / 255)
    }

    public static func textSecondary(_ scheme: ColorScheme) -> Color {
        scheme == .dark
            ? Color(red: 184 / 255, green: 184 / 255, blue: 184 / 255)
            : Color(red: 51 / 255, green: 85 / 255, blue: 113 / 255)
    }

    public static func border(_ scheme: ColorScheme) -> Color {
        textPrimary(scheme).opacity(scheme == .dark ? 0.10 : 0.18)
    }

    public static func safeColor(_ value: String?, fallback: Color) -> Color {
        guard var value = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              value.hasPrefix("#") else { return fallback }
        value.removeFirst()
        guard value.count == 6, let rgb = UInt64(value, radix: 16) else { return fallback }
        return Color(
            red: Double((rgb >> 16) & 0xff) / 255,
            green: Double((rgb >> 8) & 0xff) / 255,
            blue: Double(rgb & 0xff) / 255
        )
    }
}

public enum OariSpacing {
    public static let x1: CGFloat = 4
    public static let x2: CGFloat = 8
    public static let x3: CGFloat = 12
    public static let x4: CGFloat = 16
    public static let x5: CGFloat = 24
    public static let x6: CGFloat = 32
    public static let x7: CGFloat = 40
}

public enum OariRadius {
    public static let small: CGFloat = 8
    public static let medium: CGFloat = 12
    public static let large: CGFloat = 16
    public static let extraLarge: CGFloat = 20
    public static let modal: CGFloat = 28
    public static let pill: CGFloat = 34
}

public enum OariTypography {
    public static let title = Font.largeTitle.weight(.bold)
    public static let heading = Font.title2.weight(.bold)
    public static let action = Font.body.weight(.heavy)
    public static let label = Font.caption.weight(.heavy)
    public static let body = Font.body
    public static let technical = Font.system(.caption, design: .monospaced)
    public static let section = Font.headline.weight(.semibold)
}

public enum OariControl {
    public static let minimumHeight: CGFloat = 52
    public static let iconSize: CGFloat = 20
    public static let horizontalPadding: CGFloat = 20
}

public enum OariMotion {
    public static let fast = 0.18
    public static let standard = 0.20
    public static let slow = 0.30

    public static func animation(reduceMotion: Bool) -> Animation? {
        reduceMotion ? nil : .easeOut(duration: standard)
    }
}

public enum OariTheme: String, CaseIterable, Identifiable, Sendable {
    case system
    case light
    case dark

    public var id: String { rawValue }
    public var colorScheme: ColorScheme? {
        switch self {
        case .system: nil
        case .dark: .dark
        case .light: .light
        }
    }
}
