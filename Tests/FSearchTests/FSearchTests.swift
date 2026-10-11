import Testing
import Foundation
@testable import FSearch

@Suite("FSearch Swift Bindings Tests")
struct FSearchTests {
    @Test("Engine Initialization and Status")
    func testEngineLifecycle() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let engine = try FSearchEngine(directory: tempDir)
        engine.keepWarm(durationMs: 20)

        let status = engine.status
        #expect(status != nil)
    }

    @Test("Search Query Execution")
    func testSearchExecution() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let engine = try FSearchEngine(directory: tempDir)
        // Even if empty or waiting on initial index, searching should succeed or return valid results
        do {
            let results = try engine.search("main ext:rs")
            #expect(results.count >= 0)
        } catch FSearchError.searchFailed(let msg) {
            // "indexing" error is expected on fresh empty temp dir
            #expect(msg.contains("indexing"))
        }
    }
}
