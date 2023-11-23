const std = @import("std");

pub const auth = @import("auth.zig");
pub const http = @import("http.zig");
pub const iso8601 = @import("iso8601.zig");
pub const uri = @import("uri.zig");
comptime {
    _ = auth;
    _ = http;
    _ = iso8601;
    _ = uri;
}

/// Returns a writer which simply pumps everything written to it through
/// the given hasher. The hasher must simply provide a method of the form:
/// `fn update(hasher, bytes: []const u8) void`
pub inline fn hasherWriter(hasher: anytype) HasherWriter(@TypeOf(hasher)) {
    return .{ .context = hasher };
}
pub fn HasherWriter(comptime Hasher: type) type {
    const impl = struct {
        fn write(hasher: Hasher, bytes: []const u8) !usize {
            hasher.update(bytes);
            return bytes.len;
        }
    };
    return std.io.Writer(Hasher, error{}, impl.write);
}
