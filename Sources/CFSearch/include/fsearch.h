#ifndef FSEARCH_H
#define FSEARCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Opaque fsearch engine instance.
typedef struct FSearchEngine FSearchEngine;

/// Status of the index and daemon.
typedef struct FSearchStatus {
    bool ready;
    size_t entries;
    size_t dirs;
    size_t overlay;
    size_t removed;
    uint64_t event_id;
    size_t index_bytes;
    size_t content_docs;
    size_t content_segments;
    size_t content_bytes;
    size_t content_pending;
    bool full_disk_access;
    bool owner;
} FSearchStatus;

/// Single result from name search.
typedef struct FSearchHit {
    const char *path;
    uint8_t kind;
    uint64_t size;
    uint32_t mtime;
    int32_t score;
} FSearchHit;

/// Opaque name search results collection.
typedef struct FSearchResults FSearchResults;

/// Grep matching mode.
typedef enum FSearchGrepMode {
    FSEARCH_GREP_LITERAL = 0,
    FSEARCH_GREP_REGEX = 1,
    FSEARCH_GREP_SYMBOL = 2,
} FSearchGrepMode;

/// A matched line within a file.
typedef struct FSearchGrepLine {
    size_t line_number;
    const char *text;
} FSearchGrepLine;

/// A file containing grep matches.
typedef struct FSearchGrepFile {
    const char *path;
    const FSearchGrepLine *lines;
    size_t lines_len;
} FSearchGrepFile;

/// Opaque grep search results collection.
typedef struct FSearchGrepResult FSearchGrepResult;

// --- Engine Lifecycle ---

FSearchEngine *fsearch_engine_start(
    const char *dir,
    const char *home,
    char **err_out
);

void fsearch_engine_free(FSearchEngine *engine);

void fsearch_engine_keep_warm(FSearchEngine *engine, uint64_t duration_ms);

bool fsearch_engine_status(const FSearchEngine *engine, FSearchStatus *out_status);

char *fsearch_engine_indexing_status(const FSearchEngine *engine);

// --- Name Search ---

FSearchResults *fsearch_search(
    const FSearchEngine *engine,
    const char *query_str,
    char **err_out
);

size_t fsearch_results_len(const FSearchResults *results);

const FSearchHit *fsearch_results_data(const FSearchResults *results);

void fsearch_results_free(FSearchResults *results);

// --- Content Search (Grep) ---

FSearchGrepResult *fsearch_grep(
    const FSearchEngine *engine,
    const char *pattern,
    FSearchGrepMode mode,
    const char *filter_query,
    size_t max_matches_per_file,
    uint64_t budget_ms,
    char **err_out
);

size_t fsearch_grep_files_len(const FSearchGrepResult *res);

const FSearchGrepFile *fsearch_grep_files_data(const FSearchGrepResult *res);

size_t fsearch_grep_candidates(const FSearchGrepResult *res);

size_t fsearch_grep_read(const FSearchGrepResult *res);

bool fsearch_grep_is_complete(const FSearchGrepResult *res);

void fsearch_grep_result_free(FSearchGrepResult *res);

// --- Utility ---

void fsearch_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif // FSEARCH_H
