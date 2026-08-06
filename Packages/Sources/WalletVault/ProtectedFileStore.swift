import Foundation

struct ProtectedFileStore: Sendable {
    let directory: URL

    func prepare() throws {
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        try excludeFromBackup(directory)
    }

    func read(_ file: URL) throws -> Data {
        try Data(contentsOf: file, options: .mappedIfSafe)
    }

    func write(_ data: Data, to file: URL) throws {
        try data.write(to: file, options: [.atomic, .completeFileProtection])
        try excludeFromBackup(file)
    }

    func remove(_ file: URL) throws {
        try FileManager.default.removeItem(at: file)
    }

    func exists(_ file: URL) -> Bool {
        FileManager.default.fileExists(atPath: file.path)
    }

    func files(withExtension fileExtension: String) throws -> [URL] {
        try FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == fileExtension }
    }

    private func excludeFromBackup(_ url: URL) throws {
        var mutableURL = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try mutableURL.setResourceValues(values)
    }
}
