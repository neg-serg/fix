//! Minimal NAR serialization for hashing and adding source paths.

const std = @import("std");
const FileCache = @import("file_cache.zig").FileCache;

pub const Filter = struct {
    context: *anyopaque,
    accept: *const fn (context: *anyopaque, path: []const u8, kind: FileCache.FileKind) anyerror!bool,
};

/// Out-parameter for `serialize`: when serialization aborts on a file whose
/// type NAR cannot represent (fifo/socket/device — anything reported as
/// `.unknown`), the offending path is recorded here so callers can build the
/// Nix-style `file '<path>' has an unsupported type` diagnostic. `path` is
/// allocated with the serializer's allocator; the caller owns and frees it.
pub const Unsupported = struct {
    path: ?[]u8 = null,

    pub fn deinit(self: *Unsupported, allocator: std.mem.Allocator) void {
        if (self.path) |p| allocator.free(p);
        self.path = null;
    }
};

/// Serialize `path` to a NAR byte stream (`nix-archive-1` format), applying
/// `filter` to directory descent. Caller owns the returned buffer. This is the
/// dump the daemon's `AddToStore` (recursive/NAR ingestion) reads.
pub fn serialize(allocator: std.mem.Allocator, files: *FileCache, path: []const u8, filter: ?Filter) ![]u8 {
    return serializeReport(allocator, files, path, filter, null);
}

/// `serialize`, but records the offending path into `unsupported` (when
/// non-null) on `error.UnsupportedPathType`.
pub fn serializeReport(
    allocator: std.mem.Allocator,
    files: *FileCache,
    path: []const u8,
    filter: ?Filter,
    unsupported: ?*Unsupported,
) ![]u8 {
    return serializeCapped(allocator, files, path, filter, unsupported, FileCache.max_read_bytes);
}

/// `serializeReport` with the read cap spelled out. Files above the cap stream
/// through the writer (see `writeFileContents`), so the threshold is a parameter
/// rather than a constant read deep inside the serializer — a test (or a future
/// option) can exercise the streaming branch without moving the cache's cap.
fn serializeCapped(
    allocator: std.mem.Allocator,
    files: *FileCache,
    path: []const u8,
    filter: ?Filter,
    unsupported: ?*Unsupported,
    read_cap: usize,
) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try writeArchive(allocator, files, &out.writer, path, filter, unsupported, read_cap);
    return out.toOwnedSlice();
}

fn writeArchive(
    allocator: std.mem.Allocator,
    files: *FileCache,
    writer: *std.Io.Writer,
    path: []const u8,
    filter: ?Filter,
    unsupported: ?*Unsupported,
    read_cap: usize,
) !void {
    try writeString(writer, "nix-archive-1");
    // Nix resolves the *root* source object before serializing: a top-level
    // symlink is followed to its target, which is then dumped as that target's
    // type (e.g. a directory). Only the root is resolved — symlinks encountered
    // as directory entries are still serialized as symlink nodes (below).
    const root = try resolveRootSymlink(allocator, files, path);
    defer allocator.free(root);
    try writeNode(allocator, files, writer, root, filter, unsupported, read_cap);
}

/// Follow a chain of symlinks at the *root* of a source path, returning the
/// resolved path (caller owns it). Matches Nix: the top-level object of a
/// `filterSource`/`builtins.path`/path-coercion ingest is resolved before
/// serialization, while nested symlinks are left alone. A non-symlink root, a
/// broken/dangling chain, or a symlink cycle falls back to the original path
/// (so a dangling root still serializes as a symlink node, as before).
fn resolveRootSymlink(allocator: std.mem.Allocator, files: *FileCache, path: []const u8) ![]u8 {
    const kind = files.fileType(path) catch return allocator.dupe(u8, path);
    if (kind != .symlink) return allocator.dupe(u8, path);

    var current = try allocator.dupe(u8, path);
    errdefer allocator.free(current);
    var depth: usize = 0;
    while (depth < 256) : (depth += 1) {
        const cur_kind = files.fileType(current) catch {
            // Allocate the fallback before freeing `current`: if the dupe fails,
            // `errdefer allocator.free(current)` must be the only free of it.
            const fallback = try allocator.dupe(u8, path);
            allocator.free(current);
            return fallback;
        };
        if (cur_kind != .symlink) return current;
        const target = try files.readLink(current);
        defer allocator.free(target);
        const dir = std.fs.path.dirname(current) orelse "/";
        const next = try std.fs.path.resolve(allocator, &.{ dir, target });
        allocator.free(current);
        current = next;
    }
    // Symlink cycle: give up and serialize the original as a symlink node.
    // Allocate the fallback before freeing `current` so an allocation failure
    // leaves exactly one owner for `errdefer` to free.
    const fallback = try allocator.dupe(u8, path);
    allocator.free(current);
    return fallback;
}

pub fn hashPath(allocator: std.mem.Allocator, files: *FileCache, path: []const u8) ![]u8 {
    return hashPathFiltered(allocator, files, path, null);
}

pub fn hashPathFiltered(allocator: std.mem.Allocator, files: *FileCache, path: []const u8, filter: ?Filter) ![]u8 {
    const digest = try hashPathDigestFiltered(allocator, files, path, filter);
    const encoded = std.fmt.bytesToHex(digest, .lower);
    return allocator.dupe(u8, &encoded);
}

/// SHA-256 of a canonical NAR stream, produced incrementally. Traversal still
/// allocates bounded path/sort scratch, but never retains the archive payload.
pub fn hashPathDigest(allocator: std.mem.Allocator, files: *FileCache, path: []const u8) ![std.crypto.hash.sha2.Sha256.digest_length]u8 {
    return hashPathDigestFiltered(allocator, files, path, null);
}

pub fn hashPathDigestFiltered(
    allocator: std.mem.Allocator,
    files: *FileCache,
    path: []const u8,
    filter: ?Filter,
) ![std.crypto.hash.sha2.Sha256.digest_length]u8 {
    const Sha256 = @import("base").sha256.Sha256;
    var hashing: std.Io.Writer.Hashing(Sha256) = .init(&.{});
    try writeArchive(allocator, files, &hashing.writer, path, filter, null, FileCache.max_read_bytes);
    try hashing.writer.flush();
    var digest: [Sha256.digest_length]u8 = undefined;
    hashing.hasher.final(&digest);
    return digest;
}

/// Hex sha256 of an already-serialized NAR byte stream (caller owns result).
pub fn hashSerialized(allocator: std.mem.Allocator, nar_bytes: []const u8) ![]u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    @import("base").sha256.Sha256.hash(nar_bytes, &digest, .{});
    const encoded = std.fmt.bytesToHex(digest, .lower);
    return allocator.dupe(u8, &encoded);
}

fn writeNode(allocator: std.mem.Allocator, files: *FileCache, writer: *std.Io.Writer, path: []const u8, filter: ?Filter, unsupported: ?*Unsupported, read_cap: usize) !void {
    try writeString(writer, "(");
    switch (try files.fileType(path)) {
        .regular => {
            try writeString(writer, "type");
            try writeString(writer, "regular");
            if (try files.isExecutable(path)) {
                try writeString(writer, "executable");
                try writeString(writer, "");
            }
            try writeString(writer, "contents");
            try writeFileContents(files, writer, path, read_cap);
        },
        .directory => {
            try writeString(writer, "type");
            try writeString(writer, "directory");
            const entries = try sortedDirEntries(allocator, try files.readDir(path));
            defer allocator.free(entries);
            for (entries) |entry| {
                const child = try std.fs.path.join(allocator, &.{ path, entry.name });
                defer allocator.free(child);
                if (filter) |f| {
                    // Use the stat-accurate type (like Nix's lstat), not the
                    // readdir d_type — they can disagree (DT_UNKNOWN on some
                    // filesystems, or a bind-mounted node), and the type handed
                    // to the filter must match what serialization sees below.
                    const kind = files.fileType(child) catch entry.kind;
                    if (!try f.accept(f.context, child, kind)) continue;
                }
                try writeString(writer, "entry");
                try writeString(writer, "(");
                try writeString(writer, "name");
                try writeString(writer, entry.name);
                try writeString(writer, "node");
                try writeNode(allocator, files, writer, child, filter, unsupported, read_cap);
                try writeString(writer, ")");
            }
        },
        .symlink => {
            const target = try files.readLink(path);
            defer allocator.free(target);
            try writeString(writer, "type");
            try writeString(writer, "symlink");
            try writeString(writer, "target");
            try writeString(writer, target);
        },
        .unknown => {
            if (unsupported) |u| {
                if (u.path == null) u.path = try allocator.dupe(u8, path);
            }
            return error.UnsupportedPathType;
        },
    }
    try writeString(writer, ")");
}

/// Serialize a regular file's contents.
///
/// Files at or below `read_cap` come from the cache, which
/// usually already holds them. Larger ones are streamed in bounded chunks:
/// NAR writes the length before the contents, and a source tree may hold
/// blobs far above the read cap (a vendored tarball, a demo build), which
/// must not be materialized in memory. Nix streams every file the same way,
/// so the serialized bytes are unchanged.
fn writeFileContents(files: *FileCache, writer: *std.Io.Writer, path: []const u8, read_cap: usize) !void {
    const size = try files.fileSize(path);
    if (size <= read_cap) {
        try writeString(writer, try files.readFile(path));
        return;
    }

    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, size, .little);
    try writer.writeAll(&length);

    const io = files.io orelse return error.FileIoUnavailable;
    var file = try files.openRead(path);
    defer file.close(io);

    var buffer: [64 * 1024]u8 = undefined;
    var reader = file.readerStreaming(io, &buffer);
    var remaining: u64 = size;
    while (remaining > 0) {
        const want: usize = @intCast(@min(remaining, buffer.len));
        const chunk = try reader.interface.take(want);
        if (chunk.len == 0) return error.UnexpectedEof;
        try writer.writeAll(chunk);
        remaining -= chunk.len;
    }
    // NAR pads every string to 8 bytes, exactly as `writeString` does.
    const padding = (8 - size % 8) % 8;
    try writer.splatByteAll(0, @intCast(padding));
}

fn writeString(writer: *std.Io.Writer, text: []const u8) !void {
    var len: [8]u8 = undefined;
    std.mem.writeInt(u64, &len, text.len, .little);
    try writer.writeAll(&len);
    try writer.writeAll(text);
    const padding = (8 - text.len % 8) % 8;
    try writer.splatByteAll(0, padding);
}

fn sortedDirEntries(allocator: std.mem.Allocator, entries: []const FileCache.DirEntry) ![]FileCache.DirEntry {
    const sorted = try allocator.dupe(FileCache.DirEntry, entries);
    std.mem.sort(FileCache.DirEntry, sorted, {}, struct {
        fn lessThan(_: void, left: FileCache.DirEntry, right: FileCache.DirEntry) bool {
            return std.mem.lessThan(u8, left.name, right.name);
        }
    }.lessThan);
    return sorted;
}

test "streaming path digest matches retained canonical NAR bytes" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "payload",
        .data = "stream me without retaining a second archive",
    });
    const cwd = try std.process.currentPathAlloc(testing.io, testing.allocator);
    defer testing.allocator.free(cwd);
    const path = try std.fs.path.resolve(testing.allocator, &.{
        cwd,
        ".zig-cache",
        "tmp",
        &tmp.sub_path,
        "payload",
    });
    defer testing.allocator.free(path);

    var files = FileCache.init(testing.allocator);
    defer files.deinit();
    files.setIo(testing.io);

    const serialized = try serialize(testing.allocator, &files, path, null);
    defer testing.allocator.free(serialized);
    const retained_hash = try hashSerialized(testing.allocator, serialized);
    defer testing.allocator.free(retained_hash);

    const digest = try hashPathDigest(testing.allocator, &files, path);
    const streaming_hash = std.fmt.bytesToHex(digest, .lower);
    try testing.expectEqualStrings(retained_hash, &streaming_hash);
}

test "files above the read cap stream byte-identically to the cached path" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // 205 bytes: above the tiny cap used below, and not a multiple of 8, so the
    // streamed path has to write both the length prefix and the NAR padding.
    var payload: [205]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast('a' + (index % 26));
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "big.bin", .data = &payload });

    const cwd = try std.process.currentPathAlloc(testing.io, testing.allocator);
    defer testing.allocator.free(cwd);
    const path = try std.fs.path.resolve(testing.allocator, &.{
        cwd,
        ".zig-cache",
        "tmp",
        &tmp.sub_path,
        "big.bin",
    });
    defer testing.allocator.free(path);

    var files = FileCache.init(testing.allocator);
    defer files.deinit();
    files.setIo(testing.io);

    // The cap decides memory, never bytes: a 64-byte cap routes the file through
    // the streaming branch, and the result must equal the cached read's.
    const streamed = try serializeCapped(testing.allocator, &files, path, null, null, 64);
    defer testing.allocator.free(streamed);
    const cached = try serializeReport(testing.allocator, &files, path, null, null);
    defer testing.allocator.free(cached);

    try testing.expectEqualSlices(u8, cached, streamed);
    try testing.expect(std.mem.indexOf(u8, streamed, &payload) != null);
}
