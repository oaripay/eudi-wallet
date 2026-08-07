import SwiftUI

public extension View {
    @ViewBuilder
    func oariGlassAction(lightForeground: Bool = false) -> some View {
        if #available(iOS 26.0, *) {
            self
                .foregroundStyle(lightForeground ? .white : OariColor.textOnAction)
                .background(OariColor.action, in: .circle)
                .glassEffect(.regular.tint(OariColor.action).interactive(), in: .circle)
        } else {
            self
                .foregroundStyle(lightForeground ? .white : OariColor.textOnAction)
                .background(.ultraThinMaterial, in: Circle())
                .overlay(Circle().stroke(.white.opacity(0.28), lineWidth: 1))
                .shadow(color: .black.opacity(0.22), radius: 12, y: 6)
        }
    }
}
