import Foundation
import CFSearch

/// Entry kind matching `walk::KIND_*` and `walk::FLAG_*`.
public struct EntryKind: Equatable, Hashable, Sendable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    public static let file = EntryKind(rawValue: 0)
    public static let directory = EntryKind(rawValue: 1)
    public static let symlink = EntryKind(rawValue: 2)
    public static let other = EntryKind(rawValue: 3)

    public var isDirectory: Bool { (rawValue & 3) == 1 }
    public var isFile: Bool { (rawValue & 3) == 0 }
    public var isSymlink: Bool { (rawValue & 3) == 2 }
    public var isHidden: Bool { (rawValue & 4) != 0 }
}

/// A search result hit from name/filter search.
public struct SearchHit: Identifiable, Sendable {
    public var id: String { path }
    public let path: String
    public let kind: EntryKind
    public let size: UInt64
    public let modifiedAt: Date
    public let score: Int32

    init(cHit: FSearchHit) {
        self.path = String(cString: cHit.path)
        self.kind = EntryKind(rawValue: cHit.kind)
        self.size = cHit.size
        self.modifiedAt = Date(timeIntervalSince1970: TimeInterval(cHit.mtime))
        self.score = cHit.score
    }
}

/// A matched line within a file from grep search.
public struct GrepLine: Sendable {
    public let lineNumber: Int
    public let text: String

    init(cLine: FSearchGrepLine) {
        self.lineNumber = cLine.line_number
        self.text = String(cString: cLine.text)
    }
}

/// A file containing grep matches.
public struct GrepFile: Identifiable, Sendable {
    public var id: String { path }
    public let path: String
    public let lines: [GrepLine]

    init(cFile: FSearchGrepFile) {
        self.path = String(cString: cFile.path)
        if let linePtr = cFile.lines, cFile.lines_len > 0 {
            let buffer = UnsafeBufferPointer(start: linePtr, count: cFile.lines_len)
            self.lines = buffer.map { GrepLine(cLine: $0) }
        } else {
            self.lines = []
        }
    }
}

/// Grep matching mode.
public enum GrepMode: Int32, Sendable {
    case literal = 0
    case regex = 1
    case symbol = 2

    var cMode: FSearchGrepMode {
        switch self {
        case .literal: return FSEARCH_GREP_LITERAL
        case .regex: return FSEARCH_GREP_REGEX
        case .symbol: return FSEARCH_GREP_SYMBOL
        }
    }
}

/// Status of the fsearch engine index.
public struct EngineStatus: Sendable {
    public let isReady: Bool
    public let entries: Int
    public let directories: Int
    public let overlayEntries: Int
    public let removedEntries: Int
    public let eventId: UInt64
    public let indexBytes: Int
    public let contentDocs: Int
    public let contentSegments: Int
    public let contentBytes: Int
    public let contentPending: Int
    public let hasFullDiskAccess: Bool
    public let isOwner: Bool

    init(cStatus: FSearchStatus) {
        self.isReady = cStatus.ready
        self.entries = cStatus.entries
        self.directories = cStatus.dirs
        self.overlayEntries = cStatus.overlay
        self.removedEntries = cStatus.removed
        self.eventId = cStatus.event_id
        self.indexBytes = cStatus.index_bytes
        self.contentDocs = cStatus.content_docs
        self.contentSegments = cStatus.content_segments
        self.contentBytes = cStatus.content_bytes
        self.contentPending = cStatus.content_pending
        self.hasFullDiskAccess = cStatus.full_disk_access
        self.isOwner = cStatus.owner
    }
}

/// Complete result of a grep search.
public struct GrepResult: Sendable {
    public let files: [GrepFile]
    public let candidates: Int
    public let read: Int
    public let isComplete: Bool
}

/// Errors thrown by the FSearch engine.
public enum FSearchError: Error, LocalizedError {
    case initializationFailed(String)
    case searchFailed(String)
    case grepFailed(String)
    case engineDeallocated

    public var errorDescription: String? {
        switch self {
        case .initializationFailed(let msg): return "Engine initialization failed: \(msg)"
        case .searchFailed(let msg): return "Search failed: \(msg)"
        case .grepFailed(let msg): return "Grep failed: \(msg)"
        case .engineDeallocated: return "Engine instance has been deallocated"
        }
    }
}

/// Thread-safe Swift interface to the `fsearch` engine.
public final class FSearchEngine: @unchecked Sendable {
    private var raw: OpaquePointer?
    private let lock = NSLock()

    /// Starts an in-process fsearch engine.
    ///
    /// - Parameters:
    ///   - directory: Custom directory to store index files. Pass `nil` for default (`~/Library/Application Support/FSearch`).
    ///   - home: Custom home directory. Pass `nil` to use current user's `$HOME`.
    public init(directory: URL? = nil, home: URL? = nil) throws {
        var errPtr: UnsafeMutablePointer<CChar>? = nil
        let dirPath = directory?.path
        let homePath = home?.path

        let enginePtr = dirPath.withOptionalCString { cDir in
            homePath.withOptionalCString { cHome in
                fsearch_engine_start(cDir, cHome, &errPtr)
            }
        }

        if let err = errPtr {
            let msg = String(cString: err)
            fsearch_string_free(err)
            throw FSearchError.initializationFailed(msg)
        }

        guard let enginePtr else {
            throw FSearchError.initializationFailed("Failed to initialize engine")
        }

        self.raw = enginePtr
    }

    deinit {
        if let raw {
            fsearch_engine_free(raw)
        }
    }

    /// Keep CPU cores clocked up for the given duration (in milliseconds)
    /// to avoid frequency ramp-up latency on rapid keystrokes.
    public func keepWarm(durationMs: UInt64 = 50) {
        lock.lock()
        defer { lock.unlock() }
        guard let raw else { return }
        fsearch_engine_keep_warm(raw, durationMs)
    }

    /// Current status of the index and daemon state.
    public var status: EngineStatus? {
        lock.lock()
        defer { lock.unlock() }
        guard let raw else { return nil }

        var cStatus = FSearchStatus()
        guard fsearch_engine_status(raw, &cStatus) else {
            return nil
        }
        return EngineStatus(cStatus: cStatus)
    }

    /// Description of initial indexing progress, if currently indexing.
    public var indexingStatus: String? {
        lock.lock()
        defer { lock.unlock() }
        guard let raw else { return nil }

        guard let cStr = fsearch_engine_indexing_status(raw) else {
            return nil
        }
        defer { fsearch_string_free(cStr) }
        return String(cString: cStr)
    }

    /// Search files by name, path, extension, or filter tags.
    ///
    /// Examples:
    /// - `engine.search("main ext:rs")`
    /// - `engine.search("photo in:~/Pictures type:image")`
    public func search(_ query: String) throws -> [SearchHit] {
        lock.lock()
        guard let raw else {
            lock.unlock()
            throw FSearchError.engineDeallocated
        }
        let currentRaw = raw
        lock.unlock()

        var errPtr: UnsafeMutablePointer<CChar>? = nil
        let resultsPtr = query.withCString { cQuery in
            fsearch_search(currentRaw, cQuery, &errPtr)
        }

        if let err = errPtr {
            let msg = String(cString: err)
            fsearch_string_free(err)
            throw FSearchError.searchFailed(msg)
        }

        guard let resultsPtr else {
            return []
        }
        defer { fsearch_results_free(resultsPtr) }

        let count = fsearch_results_len(resultsPtr)
        guard count > 0, let hitsPtr = fsearch_results_data(resultsPtr) else {
            return []
        }

        let buffer = UnsafeBufferPointer(start: hitsPtr, count: count)
        return buffer.map { SearchHit(cHit: $0) }
    }

    /// Async wrapper for `search`.
    public func searchAsync(_ query: String) async throws -> [SearchHit] {
        try await Task.detached { [self] in
            try self.search(query)
        }.value
    }

    /// Search inside file contents (trigram index + disk scan).
    ///
    /// - Parameters:
    ///   - pattern: String literal, regex, or symbol.
    ///   - mode: `.literal` (default), `.regex`, or `.symbol`.
    ///   - filterQuery: Optional path/extension filter string (e.g. `in:~/Developer ext:swift`).
    ///   - maxMatchesPerFile: Maximum lines to return per file (default: 5).
    ///   - budgetMs: Search deadline budget in milliseconds (default: 250).
    public func grep(
        _ pattern: String,
        mode: GrepMode = .literal,
        filterQuery: String? = nil,
        maxMatchesPerFile: Int = 5,
        budgetMs: UInt64 = 250
    ) throws -> GrepResult {
        lock.lock()
        guard let raw else {
            lock.unlock()
            throw FSearchError.engineDeallocated
        }
        let currentRaw = raw
        lock.unlock()

        var errPtr: UnsafeMutablePointer<CChar>? = nil
        let resPtr = pattern.withCString { cPattern in
            filterQuery.withOptionalCString { cFilter in
                fsearch_grep(
                    currentRaw,
                    cPattern,
                    mode.cMode,
                    cFilter,
                    maxMatchesPerFile,
                    budgetMs,
                    &errPtr
                )
            }
        }

        if let err = errPtr {
            let msg = String(cString: err)
            fsearch_string_free(err)
            throw FSearchError.grepFailed(msg)
        }

        guard let resPtr else {
            return GrepResult(files: [], candidates: 0, read: 0, isComplete: false)
        }
        defer { fsearch_grep_result_free(resPtr) }

        let filesCount = fsearch_grep_files_len(resPtr)
        var files: [GrepFile] = []
        if filesCount > 0, let filesPtr = fsearch_grep_files_data(resPtr) {
            let buffer = UnsafeBufferPointer(start: filesPtr, count: filesCount)
            files = buffer.map { GrepFile(cFile: $0) }
        }

        return GrepResult(
            files: files,
            candidates: fsearch_grep_candidates(resPtr),
            read: fsearch_grep_read(resPtr),
            isComplete: fsearch_grep_is_complete(resPtr)
        )
    }

    /// Async wrapper for `grep`.
    public func grepAsync(
        _ pattern: String,
        mode: GrepMode = .literal,
        filterQuery: String? = nil,
        maxMatchesPerFile: Int = 5,
        budgetMs: UInt64 = 250
    ) async throws -> GrepResult {
        try await Task.detached { [self] in
            try self.grep(
                pattern,
                mode: mode,
                filterQuery: filterQuery,
                maxMatchesPerFile: maxMatchesPerFile,
                budgetMs: budgetMs
            )
        }.value
    }
}

private extension Optional where Wrapped == String {
    func withOptionalCString<R>(_ body: (UnsafePointer<CChar>?) throws -> R) rethrows -> R {
        switch self {
        case .none:
            return try body(nil)
        case .some(let str):
            return try str.withCString { try body($0) }
        }
    }
}
