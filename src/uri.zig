//! Utility code for dealing with URIs.

const std = @import("std");
const uri = @This();

/// Simple parser that can be used to check whether or not a URI path is correctly encoded.
pub const PathValidationParser = struct {
    state: State = .unreserved,

    inline fn validStandaloneChar(byte: u8) bool {
        return switch (byte) {
            'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
            '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => true,
            '/', ':', '@' => true,
            else => false,
        };
    }

    /// Returns true for as long as no issues with the constructed URI have been encountered.
    /// Must not call this function after it returns false.
    /// Use `validator.getResult()` after successfully feeding the entirety of the URI, or
    /// after this function returns false, in order to receive a diagnostic describing
    /// the validity or invalidity of the URI.
    pub fn feed(validator: *PathValidationParser, str: []const u8) bool {
        var start: usize = 0;
        while (true) switch (validator.state) {
            .invalid_char => unreachable,
            .invalid_escape_1 => unreachable,
            .invalid_escape_2 => unreachable,

            .unreserved => {
                start = for (str[start..], start..) |char, new_start| {
                    if (validStandaloneChar(char)) continue;
                    break new_start;
                } else return true;

                if (str[start] != '%') {
                    validator.state = .{ .invalid_char = str[start] };
                    return false;
                }

                start += 1;
                validator.state = .percent;
            },
            .percent => {
                if (start == str.len) return true;
                const first_escape_char = str[start];

                switch (first_escape_char) {
                    '0'...'9', 'A'...'F' => {},
                    else => {
                        validator.state = .{ .invalid_escape_1 = .{first_escape_char} };
                        return false;
                    },
                }

                start += 1;
                validator.state = .{ .percent_char = first_escape_char };
            },
            .percent_char => |first_escape_char| {
                if (start == str.len) return true;
                const second_escape_char = str[start];

                switch (second_escape_char) {
                    '0'...'9', 'A'...'F' => {},
                    else => {
                        validator.state = .{ .invalid_escape_2 = .{ first_escape_char, second_escape_char } };
                        return false;
                    },
                }

                start += 1;
                validator.state = .unreserved;
            },
        };
        return true;
    }

    pub inline fn getResult(parser: PathValidationParser) Result {
        return switch (parser.state) {
            .unreserved => .valid,
            .percent, .percent_char => .partial_escape,

            inline //
            .invalid_char,
            .invalid_escape_1,
            .invalid_escape_2,
            => |value, tag| .{ .err = @unionInit(Result.Error, @tagName(tag), value) },
        };
    }

    pub const Result = union(enum) {
        /// The URI constructed so far is valid.
        valid,
        /// The URI constructed currently ends with a partial escape sequence.
        /// It either ends with '%', or '%' followed by a hex digit.
        partial_escape,
        /// The URI constructed is invalid.
        err: Error,

        pub const Error = union(enum) {
            /// A stray invalid byte.
            invalid_char: u8,
            /// This first character in an escape sequence after the '%' is not a valid hex digit.
            invalid_escape_1: [1]u8,
            /// The second character in this escape sequence is not a valid hex digit.
            invalid_escape_2: [2]u8,
        };
    };

    const State = union(enum) {
        unreserved,

        percent,
        percent_char: u8,

        invalid_char: u8,
        invalid_escape_1: [1]u8,
        invalid_escape_2: [2]u8,
    };
};

pub const Query = struct {
    /// name
    []const u8,
    /// value
    ?[]const u8,
};

pub inline fn parseUriQuery(
    /// Must be a substring of an encoded URI query string, not including the delimiters '?' or '&'.
    name_value: []const u8,
) uri.Query {
    const eql_idx = std.mem.indexOfScalar(u8, name_value, '=');
    const name_len = eql_idx orelse name_value.len;
    return .{
        name_value[0..name_len],
        if (eql_idx) |idx| name_value[idx + 1 ..] else null,
    };
}

pub inline fn queryStringParser(
    /// Must be the encoded query string of a URI.
    queries: []const u8,
) uri.QueryStringParser {
    return .{ .queries = queries, .idx = 0 };
}
pub const QueryStringParser = struct {
    queries: []const u8,
    idx: ?usize,

    pub inline fn next(self: *uri.QueryStringParser) ?uri.Query {
        const pair_start = self.idx orelse return null;
        const pair_end = std.mem.indexOfScalarPos(u8, self.queries, pair_start, '&');
        const pair_str = self.queries[pair_start .. pair_end orelse self.queries.len];
        self.idx = if (pair_end) |idx| idx + 1 else null;
        return parseUriQuery(pair_str);
    }
};

fn testQueryIter(
    queries: []const u8,
    expected: []const uri.Query,
) !void {
    var actual = try std.ArrayList(uri.Query).initCapacity(std.testing.allocator, expected.len);
    defer actual.deinit();

    var iter = uri.queryStringParser(queries);
    while (iter.next()) |query| try actual.append(query);

    try std.testing.expectEqualDeep(expected, actual.items);
}

test uri {
    try testQueryIter("", &.{
        .{ "", null },
    });
    try testQueryIter("=", &.{
        .{ "", "" },
    });
    try testQueryIter("==", &.{
        .{ "", "=" },
    });
    try testQueryIter("&", &.{
        .{ "", null },
        .{ "", null },
    });
    try testQueryIter("&&", &.{
        .{ "", null },
        .{ "", null },
        .{ "", null },
    });
    try testQueryIter("&=", &.{
        .{ "", null },
        .{ "", "" },
    });
    try testQueryIter("=&", &.{
        .{ "", "" },
        .{ "", null },
    });
    try testQueryIter("=&=", &.{
        .{ "", "" },
        .{ "", "" },
    });
    try testQueryIter("=&=&", &.{
        .{ "", "" },
        .{ "", "" },
        .{ "", null },
    });
    try testQueryIter("&=&=", &.{
        .{ "", null },
        .{ "", "" },
        .{ "", "" },
    });

    try testQueryIter("foo", &.{
        .{ "foo", null },
    });
    try testQueryIter("foo=", &.{
        .{ "foo", "" },
    });
    try testQueryIter("=foo", &.{
        .{ "", "foo" },
    });
    try testQueryIter("foo&", &.{
        .{ "foo", null },
        .{ "", null },
    });
    try testQueryIter("&foo", &.{
        .{ "", null },
        .{ "foo", null },
    });
    try testQueryIter("foo&bar", &.{
        .{ "foo", null },
        .{ "bar", null },
    });
    try testQueryIter("&foo&bar", &.{
        .{ "", null },
        .{ "foo", null },
        .{ "bar", null },
    });
    try testQueryIter("foo&bar&", &.{
        .{ "foo", null },
        .{ "bar", null },
        .{ "", null },
    });
}
