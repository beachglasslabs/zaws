//! Simple integration of the auth logic with zig's HTTP implementation.

const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

const zaws = @import("zaws.zig");

pub const AddHeadersError = std.mem.Allocator.Error || zaws.iso8601.YearMonthDay.ParseError || error{
    MissingTimeInDateTime,
    DateTimeExtendedYear,
    MissingHost,
};

pub const AddHeadersParams = struct {
    /// "GET", "POST", "DELETE", etc.
    request_method: []const u8,

    /// The AWS API URI.
    request_uri: std.Uri,
    request_uri_already_encoded: bool,

    /// Must be the Date and Time in ISO 8601 format, ie "20130926T225743Z", for which the request should be scoped.
    /// That is to say, it will identify the resulting signature as having been created on this date at the specified time.
    date_time: []const u8,
    /// The service for which the request should be scoped.
    service: []const u8,
    /// Region for which the request should be scoped.
    region: []const u8,

    access_key_id: *const [zaws.auth.access_key_id_len]u8,
    secret_access_key: *const [zaws.auth.secret_access_key_len]u8,
    /// Must be non-null for temporary credentials.
    session_token: ?[]const u8,

    payload_sign: zaws.auth.CanonicalPayloadSign,
};

/// Adds the relevant headers to `headers` in order to sign the request it will be used for.
/// Calculates the signature using any headers already present in `headers`. Any headers which
/// should not be used as part of the signature should only be added after calling this function.
/// Asserts `headers.owned`.
pub fn sortAndAddAuthHeaders(
    allocator: std.mem.Allocator,
    headers: *std.http.Headers,
    params: AddHeadersParams,
) AddHeadersError!void {
    assert(headers.owned); // memory management without owning the fields is too complicated

    try headers.append("x-amz-date", params.date_time);
    if (params.session_token) |session_token| try headers.append("x-amz-security-token", session_token);
    if (!headers.contains("host")) {
        const host = params.request_uri.host orelse return error.MissingHost;
        try headers.append("host", host);
    }

    {
        try headers.append("x-amz-content-sha256", "");

        const payload_sign = try std.fmt.allocPrint(headers.allocator, "{}", .{params.payload_sign.fmt()});
        errdefer headers.allocator.free(payload_sign);

        const indices = headers.getIndices("x-amz-content-sha256").?;
        const idx = indices[indices.len - 1];
        headers.list.items[idx].value = payload_sign;
    }
    headers.sort();

    const date_bounded_array = blk: {
        var date_str: std.BoundedArray(u8, "2000-12-31".len) = .{};
        const time_sep_idx = std.mem.indexOfScalar(u8, params.date_time, 'T') orelse return error.MissingTimeInDateTime;
        const year_month_day = try zaws.iso8601.YearMonthDay.parse(params.date_time[0..time_sep_idx]);
        if (year_month_day.year != .basic) return error.DateTimeExtendedYear;
        year_month_day.writeTo(date_str.writer(), .dont_want_dashes) catch unreachable;
        break :blk date_str;
    };
    const date_str: []const u8 = date_bounded_array.constSlice();

    const canon_request_digest: [Sha256.digest_length]u8 = digest: {
        var canon_request_hasher = Sha256.init(.{});

        var crb = zaws.auth.canonicalRequestBuilder(zaws.hasherWriter(&canon_request_hasher));
        crb.setHttpMethod(params.request_method) catch |e| switch (e) {};
        crb.setCanonicalUri(params.request_uri.path, .{
            .already_uri_encoded = params.request_uri_already_encoded,
        }) catch |e| switch (e) {};

        if (params.request_uri.query) |queries_str| {
            var query_iter = zaws.uri.queryStringParser(queries_str);
            const queries = try allocator.alloc(zaws.uri.Query, count: {
                var query_count: usize = 0;
                while (query_iter.next() != null) query_count += 1;
                break :count query_count;
            });
            defer allocator.free(queries);

            query_iter = zaws.uri.queryStringParser(queries_str);
            for (queries) |*query| query.* = query_iter.next().?;
            assert(query_iter.next() == null);

            std.sort.block(zaws.uri.Query, queries, {}, struct {
                fn lessThan(_: void, lhs: zaws.uri.Query, rhs: zaws.uri.Query) bool {
                    const lhs_name, _ = lhs;
                    const rhs_name, _ = rhs;
                    return std.mem.lessThan(u8, lhs_name, rhs_name);
                }
            }.lessThan);

            for (queries) |query| {
                const name, const value = query;
                crb.addQueryName(name) catch |e| switch (e) {};
                crb.setQueryValue(value orelse "") catch |e| switch (e) {};
            }
        }
        crb.endQueryString() catch |e| switch (e) {};

        for (headers.list.items) |header| {
            crb.addCanonHeaderName(header.name) catch |e| switch (e) {};
            crb.setCanonHeaderValue(header.value) catch |e| switch (e) {};
        }
        crb.endCanonHeaders() catch |e| switch (e) {};

        for (headers.list.items) |header| {
            crb.addSignedHeader(header.name) catch |e| switch (e) {};
        }
        crb.setPayloadSign(params.payload_sign) catch |e| switch (e) {};

        break :digest canon_request_hasher.finalResult();
    };

    const scope: zaws.auth.Scope = .{
        .date = date_str,
        .region = params.region,
        .service = params.service,
    };
    const sts: zaws.auth.StringToSign = .{
        .algorithm = "AWS4-HMAC-SHA256",
        .date_time = params.date_time,
        .scope = scope,
        .canon_request_digest = &canon_request_digest,
    };

    const signing_key = zaws.auth.calcSigningKey(params.secret_access_key, scope);
    const signature = zaws.auth.calcSignature(&signing_key, sts);

    const auth_header_value: []const u8 = blk: {
        var auth_header_value: std.ArrayListUnmanaged(u8) = .{};
        defer auth_header_value.deinit(headers.allocator);

        var ahb = zaws.auth.authorizationHeaderBuilder(auth_header_value.writer(headers.allocator));
        try ahb.setAlgorithm(sts.algorithm);
        try ahb.setCredential(params.access_key_id, scope);
        for (headers.list.items) |header| try ahb.addSignedHeader(header.name);
        try ahb.setSignature(&signature);

        break :blk try auth_header_value.toOwnedSlice(headers.allocator);
    };
    errdefer headers.allocator.free(auth_header_value);

    {
        try headers.append("Authorization", "");
        const indices = headers.getIndices("Authorization").?;
        const idx = indices[indices.len - 1];
        headers.list.items[idx].value = auth_header_value;
    }
    headers.sort();
}

fn testSortAndAddAuthHeaders(
    params: AddHeadersParams,
    existing_headers: []const struct { []const u8, []const []const u8 },
    expected_headers: []const struct { []const u8, []const []const u8 },
) !void {
    var expected = std.http.Headers.init(std.testing.allocator);
    defer expected.deinit();
    for (expected_headers) |header| {
        const name, const values = header;
        for (values) |value| try expected.append(name, value);
    }
    expected.sort();

    var actual = std.http.Headers.init(std.testing.allocator);
    defer actual.deinit();
    for (existing_headers) |header| {
        const name, const values = header;
        for (values) |value| try actual.append(name, value);
    }
    try sortAndAddAuthHeaders(std.testing.allocator, &actual, params);

    const expected_str = try std.fmt.allocPrint(std.testing.allocator, "{}", .{expected});
    defer std.testing.allocator.free(expected_str);

    const actual_str = try std.fmt.allocPrint(std.testing.allocator, "{}", .{actual});
    defer std.testing.allocator.free(actual_str);

    try std.testing.expectEqualStrings(expected_str, actual_str);
}
test sortAndAddAuthHeaders {
    try testSortAndAddAuthHeaders(
        .{
            .request_method = "GET",
            .request_uri = std.Uri.parse("https://examplebucket.s3.amazonaws.com/test.txt") catch unreachable,
            .request_uri_already_encoded = true,

            .date_time = "20130524T000000Z",
            .service = "s3",
            .region = "us-east-1",

            .access_key_id = "AKIAIOSFODNN7EXAMPLE",
            .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            .session_token = null,

            .payload_sign = .{ .digest = &comptime hexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") catch unreachable },
        },
        &.{
            .{ "host", &.{"examplebucket.s3.amazonaws.com"} },
            .{ "range", &.{"bytes=0-9"} },
        },
        &.{
            .{
                "authorization", &.{"AWS4-HMAC-SHA256 " ++
                    "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " ++
                    "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, " ++
                    "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"},
            },
            .{ "host", &.{"examplebucket.s3.amazonaws.com"} },
            .{ "range", &.{"bytes=0-9"} },
            .{ "x-amz-content-sha256", &.{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"} },
            .{ "x-amz-date", &.{"20130524T000000Z"} },
        },
    );
    try testSortAndAddAuthHeaders(
        .{
            .request_method = "PUT",
            .request_uri = std.Uri.parse("https://examplebucket.s3.amazonaws.com/test%24file.text") catch unreachable,
            .request_uri_already_encoded = true,

            .date_time = "20130524T000000Z",
            .service = "s3",
            .region = "us-east-1",

            .access_key_id = "AKIAIOSFODNN7EXAMPLE",
            .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            .session_token = null,

            .payload_sign = .{ .digest = &comptime hexToBytes("44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072") catch unreachable },
        },
        &.{
            .{ "date", &.{"Fri, 24 May 2013 00:00:00 GMT"} },
            .{ "x-amz-storage-class", &.{"REDUCED_REDUNDANCY"} },
        },
        &.{
            .{
                "authorization", &.{"AWS4-HMAC-SHA256 " ++
                    "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " ++
                    "SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, " ++
                    "Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"},
            },
            .{ "date", &.{"Fri, 24 May 2013 00:00:00 GMT"} },
            .{ "host", &.{"examplebucket.s3.amazonaws.com"} },
            .{ "x-amz-content-sha256", &.{"44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"} },
            .{ "x-amz-date", &.{"20130524T000000Z"} },
            .{ "x-amz-storage-class", &.{"REDUCED_REDUNDANCY"} },
        },
    );
    try testSortAndAddAuthHeaders(
        .{
            .request_method = "GET",
            .request_uri = std.Uri.parse("https://examplebucket.s3.amazonaws.com/?lifecycle") catch unreachable,
            .request_uri_already_encoded = true,

            .date_time = "20130524T000000Z",
            .service = "s3",
            .region = "us-east-1",

            .access_key_id = "AKIAIOSFODNN7EXAMPLE",
            .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            .session_token = null,

            .payload_sign = .{ .digest = &comptime hexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") catch unreachable },
        },
        &.{},
        &.{
            .{
                "authorization", &.{"AWS4-HMAC-SHA256 " ++
                    "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " ++
                    "SignedHeaders=host;x-amz-content-sha256;x-amz-date, " ++
                    "Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"},
            },
            .{ "host", &.{"examplebucket.s3.amazonaws.com"} },
            .{ "x-amz-content-sha256", &.{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"} },
            .{ "x-amz-date", &.{"20130524T000000Z"} },
        },
    );
    try testSortAndAddAuthHeaders(
        .{
            .request_method = "GET",
            .request_uri = std.Uri.parse("https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J") catch unreachable,
            .request_uri_already_encoded = true,

            .date_time = "20130524T000000Z",
            .service = "s3",
            .region = "us-east-1",

            .access_key_id = "AKIAIOSFODNN7EXAMPLE",
            .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            .session_token = null,

            .payload_sign = .{ .digest = &comptime hexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") catch unreachable },
        },
        &.{},
        &.{
            .{
                "authorization", &.{"AWS4-HMAC-SHA256 " ++
                    "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " ++
                    "SignedHeaders=host;x-amz-content-sha256;x-amz-date, " ++
                    "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"},
            },
            .{ "host", &.{"examplebucket.s3.amazonaws.com"} },
            .{ "x-amz-content-sha256", &.{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"} },
            .{ "x-amz-date", &.{"20130524T000000Z"} },
        },
    );
}

inline fn hexToBytes(hex_str: anytype) ![@divExact(hex_str.len, 2)]u8 {
    var result: [@divExact(hex_str.len, 2)]u8 = undefined;
    const bytes = try std.fmt.hexToBytes(&result, hex_str);
    assert(bytes.len == result.len);
    assert(bytes.ptr == &result);
    return result;
}
