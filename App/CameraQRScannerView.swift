import SwiftUI
import UIKit
import VisionKit
import OariDesignSystem

struct CameraQRScannerSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var scannerError: String?
    @State private var didRecognizeCode = false
    @State private var pendingCode: String?
    let onCode: @MainActor @Sendable (String) -> Void

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            if let scannerError {
                unavailableView(message: scannerError)
            } else if DataScannerViewController.isSupported,
                      DataScannerViewController.isAvailable {
                CameraQRScannerView { code in
                    didRecognizeCode = true
                    pendingCode = code
                    UINotificationFeedbackGenerator().notificationOccurred(.success)
                    dismiss()
                } onFailure: {
                    scannerError = "Camera access was interrupted or denied. Paste the wallet code instead."
                }
                .ignoresSafeArea()
                scannerOverlay
            } else {
                unavailableView(message: "Paste the wallet code instead, or use a physical device with camera access.")
            }
        }
        .statusBarHidden()
        .onDisappear {
            guard let pendingCode else { return }
            self.pendingCode = nil
            onCode(pendingCode)
        }
    }

    private var scannerOverlay: some View {
        ZStack {
            GeometryReader { proxy in
                let frameSize = min(proxy.size.width - 64, 210)
                ZStack {
                    LinearGradient(
                        colors: [.black.opacity(0.72), .clear, .black.opacity(0.78)],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                    .allowsHitTesting(false)

                    Color.black.opacity(0.38)
                        .mask {
                            Rectangle()
                                .overlay {
                                    RoundedRectangle(cornerRadius: 0, style: .continuous)
                                        .frame(width: frameSize, height: frameSize)
                                        .blendMode(.destinationOut)
                                }
                                .compositingGroup()
                        }
                        .allowsHitTesting(false)

                    ScannerCorners()
                        .stroke(
                            didRecognizeCode ? Color.green : OariColor.action,
                            style: StrokeStyle(lineWidth: 5, lineCap: .round, lineJoin: .round)
                        )
                        .frame(width: frameSize, height: frameSize)
                        .shadow(color: .black.opacity(0.35), radius: 8, y: 3)
                        .overlay {
                            if didRecognizeCode {
                                ProgressView()
                                    .controlSize(.large)
                                    .tint(.white)
                                    .padding(18)
                                    .background(.black.opacity(0.65), in: Circle())
                                    .transition(.scale.combined(with: .opacity))
                            }
                        }
                        .animation(reduceMotion ? nil : .spring(response: 0.28), value: didRecognizeCode)
                }
            }
            .ignoresSafeArea()

            VStack {
                scannerHeader
                Spacer()
            }
            .padding(.horizontal, 20)
            .padding(.top, 14)
        }
    }

    private var scannerHeader: some View {
        HStack {
            scannerButton(systemImage: "xmark", label: "Close camera scanner") {
                dismiss()
            }
            .accessibilityIdentifier("scanner.camera-close")
            Spacer()
        }
    }

    @ViewBuilder
    private func scannerButton(
        systemImage: String,
        label: String,
        action: @escaping () -> Void
    ) -> some View {
        if #available(iOS 26.0, *) {
            Button(action: action) {
                scannerButtonLabel(systemImage: systemImage)
            }
            .buttonStyle(.glass)
            .buttonBorderShape(.circle)
            .accessibilityLabel(label)
        } else {
            Button(action: action) {
                scannerButtonLabel(systemImage: systemImage)
            }
            .buttonStyle(.bordered)
            .buttonBorderShape(.circle)
            .tint(.black.opacity(0.5))
            .accessibilityLabel(label)
        }
    }

    private func scannerButtonLabel(systemImage: String) -> some View {
        Image(systemName: systemImage)
            .font(.system(size: 17, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: 24, height: 24)
    }

    private func unavailableView(message: String) -> some View {
        VStack(spacing: OariSpacing.x5) {
            Image(systemName: "camera.fill")
                .font(.system(size: 42, weight: .semibold))
                .foregroundStyle(OariColor.action)
                .frame(width: 88, height: 88)
                .background(.white.opacity(0.1), in: RoundedRectangle(cornerRadius: 26, style: .continuous))
            VStack(spacing: OariSpacing.x2) {
                Text("Camera scanning unavailable")
                    .font(OariTypography.heading)
                Text(message)
                    .font(.subheadline)
                    .foregroundStyle(.white.opacity(0.72))
                    .multilineTextAlignment(.center)
            }
            Button("Close and paste code") { dismiss() }
                .buttonStyle(OariPrimaryButtonStyle())
                .accessibilityIdentifier("scanner.camera-close")
        }
        .foregroundStyle(.white)
        .padding(OariSpacing.x6)
        .accessibilityIdentifier("scanner.camera-unavailable")
    }
}

private struct ScannerCorners: Shape {
    func path(in rect: CGRect) -> Path {
        let length: CGFloat = 54
        var path = Path()
        path.move(to: CGPoint(x: 0, y: length))
        path.addLine(to: CGPoint(x: 0, y: 0))
        path.addLine(to: CGPoint(x: length, y: 0))
        path.move(to: CGPoint(x: rect.maxX - length, y: 0))
        path.addLine(to: CGPoint(x: rect.maxX, y: 0))
        path.addLine(to: CGPoint(x: rect.maxX, y: length))
        path.move(to: CGPoint(x: rect.maxX, y: rect.maxY - length))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY))
        path.addLine(to: CGPoint(x: rect.maxX - length, y: rect.maxY))
        path.move(to: CGPoint(x: length, y: rect.maxY))
        path.addLine(to: CGPoint(x: 0, y: rect.maxY))
        path.addLine(to: CGPoint(x: 0, y: rect.maxY - length))
        return path
    }
}

private struct CameraQRScannerView: UIViewControllerRepresentable {
    let onCode: @MainActor @Sendable (String) -> Void
    let onFailure: @MainActor @Sendable () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onCode: onCode, onFailure: onFailure)
    }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let controller = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            recognizesMultipleItems: false,
            isHighFrameRateTrackingEnabled: false,
            isPinchToZoomEnabled: true,
            isGuidanceEnabled: false,
            isHighlightingEnabled: false
        )
        controller.delegate = context.coordinator
        do {
            try controller.startScanning()
        } catch {
            onFailure()
        }
        return controller
    }

    func updateUIViewController(
        _ uiViewController: DataScannerViewController,
        context: Context
    ) {}

    static func dismantleUIViewController(
        _ uiViewController: DataScannerViewController,
        coordinator: Coordinator
    ) {
        uiViewController.stopScanning()
    }

    @MainActor
    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let onCode: @MainActor @Sendable (String) -> Void
        private let onFailure: @MainActor @Sendable () -> Void
        private var hasDeliveredCode = false

        init(
            onCode: @escaping @MainActor @Sendable (String) -> Void,
            onFailure: @escaping @MainActor @Sendable () -> Void
        ) {
            self.onCode = onCode
            self.onFailure = onFailure
        }

        func dataScanner(
            _ dataScanner: DataScannerViewController,
            becameUnavailableWithError error: DataScannerViewController.ScanningUnavailable
        ) {
            onFailure()
        }

        func dataScanner(
            _ dataScanner: DataScannerViewController,
            didAdd addedItems: [RecognizedItem],
            allItems: [RecognizedItem]
        ) {
            guard !hasDeliveredCode else { return }
            for item in addedItems {
                guard case let .barcode(barcode) = item,
                      let code = barcode.payloadStringValue,
                      !code.isEmpty else { continue }
                hasDeliveredCode = true
                dataScanner.stopScanning()
                onCode(code)
                return
            }
        }
    }
}
