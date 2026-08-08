2import SwiftUI
import VisionKit
import OariDesignSystem

struct CameraQRScannerSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var scannerError: String?
    let onCode: @MainActor @Sendable (String) -> Void

    var body: some View {
        ZStack(alignment: .topLeading) {
            Color.black.ignoresSafeArea()
            Group {
                if let scannerError {
                    ContentUnavailableView(
                        "Camera scanning unavailable",
                        systemImage: "camera.fill",
                        description: Text(scannerError)
                    )
                    .accessibilityIdentifier("scanner.camera-unavailable")
                } else if DataScannerViewController.isSupported,
                   DataScannerViewController.isAvailable {
                    CameraQRScannerView { code in
                        onCode(code)
                        dismiss()
                    } onFailure: {
                        scannerError = "Camera access was interrupted or denied. Paste the wallet code instead."
                    }
                } else {
                    ContentUnavailableView(
                        "Camera scanning unavailable",
                        systemImage: "camera.fill",
                        description: Text("Paste the wallet code instead, or use a physical device with camera access.")
                    )
                    .accessibilityIdentifier("scanner.camera-unavailable")
                }
            }
            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark")
                    .font(.system(size: 17, weight: .bold))
                    .foregroundStyle(.white)
                    .frame(width: 46, height: 46)
                    .oariGlassAction(lightForeground: true)
            }
            .accessibilityLabel("Close camera scanner")
            .accessibilityIdentifier("scanner.camera-close")
            .padding(.leading, 20)
            .padding(.top, 14)
        }
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
            isGuidanceEnabled: true,
            isHighlightingEnabled: true
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
                onCode(code)
                return
            }
        }
    }
}
