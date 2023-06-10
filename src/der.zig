const std = @import("std");
const builtin = @import("builtin");

pub const Asn1 = struct {
    pub const Identifier = packed struct(u8) {
        tag: Tag,
        pc: PC,
        class: Class,

        pub const Class = enum(u2) {
            universal,
            application,
            context_specific,
            private,
        };

        pub const PC = enum(u1) {
            primitive,
            constructed,
        };

        pub const Tag = enum(u5) {
            boolean = 1,
            integer = 2,
            bitstring = 3,
            octetstring = 4,
            null = 5,
            object_identifier = 6,
            utf8_string = 12,
            sequence = 16,
            set = 17,
            numeric_string = 18,
            printable_string = 19,
            t61string = 20,
            videotex_string = 21,
            ia5string = 22,
            utc_time = 23,
            graphic_string = 25,
            generalized_time = 24,
            visible_string = 26,
            general_string = 27,
            universal_string = 28,
            bmp_string = 30,
            _,
        };
    };

    pub const ObjectIdentifier = []const u64;

    fn validateObjectIdentifier(comptime oid: ObjectIdentifier) bool {
        if (oid.len < 2)
            return false;

        // X.690: 8.19.4:
        // The numerical value of the first subidentifier is derived from the values of the first two object identifier components
        // in the object identifier value being encoded, using the formula:
        // (X*40) + Y
        // where X is the value of the first object identifier component and Y is the value of the second object identifier component.
        // NOTE – This packing of the first two object identifier components recognizes that only three values are allocated from the root node,
        // and at most 39 subsequent values from nodes reached by X = 0 and X = 1.
        if (oid[0] > 2 or (oid[0] != 2 and oid[1] >= 40))
            return false;

        return true;
    }

    pub fn asRawObjectIdentifier(comptime oid: ObjectIdentifier) RawObjectIdentifier {
        if (!validateObjectIdentifier(oid)) @compileError("invalid oid");

        var ret = asBase128Int(oid[0] * 40 + oid[1]);
        for (oid[2..]) |o| {
            ret = ret ++ asBase128Int(o);
        }
        return ret;
    }

    fn asBase128Int(comptime n: u64) []const u8 {
        var ret: []const u8 = "";

        var length = 0;
        if (n == 0) {
            length = 1;
        } else {
            var i = n;
            while (i > 0) : (i >>= 7) {
                length += 1;
            }
        }

        length -= 1;
        while (length >= 0) : (length -= 1) {
            var o = @truncate(u8, n >> length * 7) & 0x7f;
            if (length != 0) {
                o |= 0x80;
            }
            ret = ret ++ [_]u8{o};
        }

        return ret;
    }

    test "asRawObjectIdentifier" {
        try std.testing.expectEqualSlices(u8, &[_]u8{0x2B}, comptime asRawObjectIdentifier(&[_]u64{ 1, 3 }));
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x2B, 0x65, 0x70 }, comptime asRawObjectIdentifier(&[_]u64{ 1, 3, 101, 112 }));
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x2B, 0x65, 0x71 }, comptime asRawObjectIdentifier(&[_]u64{ 1, 3, 101, 113 }));

        const sha256WithRSA_OID = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };
        try std.testing.expectEqualSlices(u8, &sha256WithRSA_OID, comptime asRawObjectIdentifier(&[_]u64{ 1, 2, 840, 113549, 1, 1, 11 }));
    }

    // RawObjectIdentifier is a ObjectIdentifier encoded in DER format.
    // It can be compared using std.mem.eql, there is exacly one possible encoding
    // of every ObjectIdentifier.
    pub const RawObjectIdentifier = []const u8;

    pub const BitString = struct {
        // padding_bits represents the amount of ending bits of the
        // last byte that are not part of the actual value.
        // padding_bits must always be equal to 0 when bytes.len == 0.
        padding_bits: u3,

        // All bits that are ignored (specified in padding_bits) must be set to 0.
        bytes: []const u8,
    };

    // Contains a two's complement (big-endian, at least one byte long)
    // representation of an integer. It encoded in the shortest possible form.
    pub const Integer = struct {
        raw: []const u8,

        pub fn signedness(self: Integer) std.builtin.Signedness {
            if (self.raw[0] & 0x80 == 0x80) {
                return .signed;
            } else {
                return .unsigned;
            }
        }

        // Returns null when T is too small to represent the Integer.
        pub fn as(self: Integer, comptime T: type) ?T {
            if (@typeInfo(T).Int.bits < 8 or @typeInfo(T).Int.bits % 8 != 0 or @typeInfo(T).Int.signedness != .unsigned)
                @compileError("unsupported type");

            const bytes = @typeInfo(T).Int.bits / 8;

            // negative integer
            if (self.raw[0] & 0x80 == 0x80) return null;

            var raw = self.raw;
            if (bytes > self.raw.len) {
                if (bytes == raw.len - 1 and raw[0] == 0) {
                    // Skip the first zero byte, it was added, so that
                    // the Integer is not interpreted as a negative number.
                    raw = raw[1..];
                } else return null;
            }

            var ret: T = 0;
            for (raw) |byte| {
                if (bytes > 8) {
                    ret <<= 8;
                }
                ret |= byte;
            }
            ret <<= @intCast(std.math.Log2Int(T), 8 * (bytes - raw.len));
            return ret;
        }
    };
};

test {
    _ = Asn1;
    _ = Asn1.BitString;
}

pub const DerDecoder = struct {
    data: []const u8,

    pub const Element = struct {
        tag: u8,
        data: []const u8,
    };

    fn parseInteger(bytes: []const u8) !Asn1.Integer {
        // Integer has a minumum length of 1.
        if (bytes.len == 0) return error.InvalidEncoding;
        if (bytes.len == 1) return .{ .raw = bytes };

        // Not minimally encoded.
        // Integer might be prefixed with 0, so that it is not intepreted as negative.
        if (bytes[0] == 0 and bytes[1] & 0x80 == 0) return error.InvalidEncoding;
        // The first byte is unnecessary, removing it will result in the
        // same negative interpretation.
        if (bytes[0] == 0xff and bytes[1] & 0x80 == 0x80) return error.InvalidEncoding;

        return .{ .raw = bytes };
    }

    fn parseBitString(bytes: []const u8) !Asn1.BitString {
        if (bytes.len == 0) return error.InvalidEncoding;

        // ITU-T X690: 8.6.2.2 The initial octet shall encode, as an unsigned binary
        // integer with bit 1 as the least significant bit, the number of
        // unused bits in the final subsequent octet. The number shall be in the range zero to seven.
        if (bytes[0] > 7) return error.InvalidEncoding;
        const padding_bits: u3 = @intCast(u3, bytes[0]);

        // ITU-T X690: 8.6.2.2
        // If the bitstring is empty, there shall be no subsequent octets, and the initial octet shall be zero.
        if (bytes.len == 1 and padding_bits != 0) return error.InvalidEncoding;

        // ITU-T X690: 11.2.1
        // Each unused bit in the final octet of the encoding of a bit string value shall be set to zero.
        if (@ctz(bytes[bytes.len - 1]) < padding_bits) return error.InvalidEncoding;

        return .{
            .padding_bits = padding_bits,
            .bytes = bytes[1..],
        };
    }

    fn parseNamedBitString(bytes: []const u8) !Asn1.BitString {
        const bit_string = try parseBitString(bytes);

        // ITU-T X.680: 22.7:
        // When a "NamedBitList" is used in defining a bitstring type ASN.1 encoding rules are free to add (or remove)
        // arbitrarily any trailing 0 bits to (or from) values that are being encoded or decoded. Application designers should
        // therefore ensure that different semantics are not associated with such values which differ only in the number of trailing
        // 0 bits.
        // ITU-T X690 11.2.2:
        // Where Rec. ITU-T X.680 22.7, applies, the bitstring shall have all trailing 0 bits removed before it is encoded.
        // NOTE 2 – If a bitstring value has no 1 bits, then an encoder shall encode the value with a length of 1 and an initial octet set to 0.
        if (bit_string.bytes.len > 0 and bit_string.bytes[bit_string.bytes.len - 1] == 0) return error.InvalidEncoding;

        return bit_string;
    }

    pub fn parseRawObjectIdentifier(bytes: []const u8) !Asn1.RawObjectIdentifier {
        if (bytes.len == 0 or bytes[bytes.len - 1] & 0x80 != 0) return error.InvalidEncoding;

        var start: usize = 0;

        for (bytes, 0..) |v, i| {
            // ITU-T X.690, section 8.19.2:
            // The subidentifier shall be encoded in the fewest possible octets,
            // that is, the leading octet of the subidentifier shall not have the value 0x80.
            if (i == start and v == 0x80) return error.InvalidEncoding;
            if (v & 0x80 == 0) start = i + 1;
        }

        if (start == 0) return error.InvalidEncoding;

        return bytes;
    }

    fn parseBoolean(bytes: []const u8) !bool {
        if (bytes.len != 1) return error.InvalidEncoding;
        if (bytes[0] == 0) return false;
        if (bytes[0] == 0xff) return true;
        return error.InvalidEncoding;
    }

    pub fn getBitStringWithTag(self: *DerDecoder, tag: u8) !Asn1.BitString {
        return parseBitString(try self.getElementWithTag(tag));
    }

    pub fn getNamedBitStringWithTag(self: *DerDecoder, tag: u8) !Asn1.BitString {
        return parseNamedBitString(try self.getElementWithTag(tag));
    }

    pub fn getRawObjectIdentifierWithTag(self: *DerDecoder, tag: u8) !Asn1.RawObjectIdentifier {
        return parseRawObjectIdentifier(try self.getElementWithTag(tag));
    }

    pub fn getBooleanWithTag(self: *DerDecoder, tag: u8) !?bool {
        return parseBoolean(try self.getElementWithTag(tag));
    }

    pub fn getIntegerBytesWithTag(self: *DerDecoder, tag: u8) !Asn1.Integer {
        return parseInteger(try self.getElementWithTag(tag));
    }

    pub fn getIntegerBytesWithDefaultWithTag(self: *DerDecoder, tag: u8) !Asn1.Integer {
        return parseInteger(try self.getElementWithTag(tag));
    }

    pub fn getOptionalBitStringWithTag(self: *DerDecoder, tag: u8) !?Asn1.BitString {
        if (try self.getOptionalElementWithTag(tag)) |bytes| return try parseBitString(bytes);
        return null;
    }

    pub fn getOptionalIntegerBytesWithTag(self: *DerDecoder, tag: u8) !?Asn1.Integer {
        if (try self.getOptionalElementWithTag(tag)) |bytes| return try parseInteger(bytes);
        return null;
    }

    pub fn getBooleanWithDefaultWithTag(self: *DerDecoder, default: bool, tag: u8) !bool {
        if (try self.getOptionalElementWithTag(tag)) |bytes| {
            const value = try parseBoolean(bytes);
            // ITU-T X690: 11.5 Set and sequence components with default value
            // The encoding of a set value or sequence value shall not include
            // an encoding for any component value which is equal to its default value.
            if (value == default) return error.InvalidEncoding;
            return value;
        }
        return default;
    }

    pub fn getOptionalElementExplicit(self: *DerDecoder, tag: u8) !?Element {
        if (self.peekTag()) |t| if (t == tag) return try self.getElementExplicit(tag);
        return null;
    }

    pub fn getElementExplicit(self: *DerDecoder, tag: u8) !Element {
        var explicit = DerDecoder{ .data = try self.getElementWithTag(tag) };
        const el = try explicit.getElement();
        if (!explicit.empty()) return error.InvalidEncoding;
        return el;
    }

    pub fn getOptionalElementWithTag(self: *DerDecoder, tag: u8) !?[]const u8 {
        if (self.peekTag()) |t| {
            if (tag != t) return null;
            const e = try self.getElement();
            return e.data;
        }
        return null;
    }

    pub fn getElementWithTag(self: *DerDecoder, tag: u8) ![]const u8 {
        const e = try self.getElement();
        if (e.tag != tag) return error.InvalidEncoding;
        return e.data;
    }

    fn peekTag(self: *DerDecoder) ?u8 {
        if (self.empty()) return null;
        return self.data[0];
    }

    pub fn empty(self: *DerDecoder) bool {
        return self.data.len == 0;
    }

    pub fn getElement(self: *DerDecoder) !Element {
        if (self.data.len < 2) return error.InvalidEncoding;
        const tag = self.data[0];
        const len = self.data[1];
        if (len & 0b10000000 == 0) {
            if (self.data.len < 2 + len) return error.InvalidEncoding;
            defer self.data = self.data[2 + len ..];
            return .{
                .tag = tag,
                .data = self.data[2 .. 2 + len],
            };
        } else {
            const len_bytes = len & 0b01111111;
            if (len_bytes == 0 or len_bytes > 4 or self.data.len < 2 + len_bytes) return error.InvalidEncoding;
            const length = blk: {
                var l: u32 = 0;
                for (self.data[2 .. 2 + len_bytes]) |byte| {
                    l <<= 8;
                    l |= @intCast(u32, byte);
                }
                break :blk l;
            };

            if (length <= 128) return error.InvalidEncoding;
            if (length & @intCast(u32, std.math.maxInt(u8)) << @intCast(u5, (8 * (len_bytes - 1))) == 0) return error.InvalidEncoding;

            if (self.data.len < 2 + len_bytes + length) return error.InvalidEncoding;
            defer self.data = self.data[2 + len_bytes + length ..];
            return .{
                .tag = tag,
                .data = self.data[2 + len_bytes .. 2 + len_bytes + length],
            };
        }
    }
};

pub const DerBuilder = struct {
    list: std.ArrayList(u8),
    depth: if (builtin.mode == .Debug) usize else u0 = 0,

    pub const Prefixed = struct {
        startLen: usize,
    };

    pub fn newPrefixed(self: *DerBuilder, tag: u8) !Prefixed {
        if (builtin.mode == .Debug) self.depth += 1;

        try self.list.appendSlice(&[_]u8{ tag, 0 });
        return .{ .startLen = self.list.items.len };
    }

    pub fn endPrefixed(self: *DerBuilder, p: Prefixed) !void {
        if (builtin.mode == .Debug) self.depth -= 1;

        const endLen = self.list.items.len;
        var len = endLen - p.startLen;
        if (len < 0b10000000) {
            self.list.items[p.startLen - 1] = @intCast(u8, len);
        } else {
            var lenBytes: u8 = if (len > std.math.maxInt(u24)) @panic("value too big") else if (len > std.math.maxInt(u16)) 3 else if (len > std.math.maxInt(u8)) 2 else 1;
            try self.list.appendNTimes(undefined, lenBytes);
            std.mem.copyBackwards(u8, self.list.items[p.startLen + lenBytes ..], self.list.items[p.startLen..endLen]);

            self.list.items[p.startLen - 1] = 0b10000000 | lenBytes;

            var len_bytes = self.list.items[p.startLen .. p.startLen + lenBytes];
            var i: isize = @intCast(isize, len_bytes.len) - 1;
            while (i >= 0) {
                len_bytes[@intCast(usize, i)] = @truncate(u8, len);
                len >>= 8;
                i -= 1;
            }
        }
    }

    pub fn deinit(self: *DerBuilder) void {
        if (builtin.mode == .Debug and self.depth != 0) @panic("deinit() called on derBuilder when depth != 0");
        self.list.deinit();
    }

    // appendOID appends OID to the builder, oid must fit into
    // the ene byte length DER encoding.
    pub fn appendOID(self: *DerBuilder, oid: []const u8) !void {
        try self.list.append(0x06);
        try self.list.append(@intCast(u8, oid.len));
        try self.list.appendSlice(oid);
    }
};

test "der builder small length" {
    var builder = DerBuilder{ .list = std.ArrayList(u8).init(std.testing.allocator) };
    defer builder.deinit();

    var prefixed = try builder.newPrefixed(10);
    try builder.list.append(1);
    try builder.list.append(1);
    try builder.list.append(1);

    var prefixed2 = try builder.newPrefixed(12);
    try builder.list.append(1);
    try builder.endPrefixed(prefixed2);

    try builder.endPrefixed(prefixed);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 6, 1, 1, 1, 12, 1, 1 }, builder.list.items);
}

test "der builder big length" {
    var builder = DerBuilder{ .list = std.ArrayList(u8).init(std.testing.allocator) };
    defer builder.deinit();

    var content = "aa" ** 120;

    var prefixed = try builder.newPrefixed(10);
    try builder.list.appendSlice(content);
    try builder.list.appendSlice(content);

    var prefixed2 = try builder.newPrefixed(12);
    try builder.list.appendSlice(content);
    try builder.endPrefixed(prefixed2);

    try builder.endPrefixed(prefixed);

    var expect = [_]u8{ 10, 0b10000010, 0x02, 0xD3 } ++ content ++ content ++ [_]u8{ 12, 0b10000001, 240 } ++ content;

    try std.testing.expectEqualSlices(u8, expect, builder.list.items);
}

pub fn isAscii(str: []const u8) bool {
    for (str) |char| {
        if (!std.ascii.isASCII(char)) return false;
    }
    return true;
}

pub fn isValidPrintableString(str: []const u8, allow_asterisk: bool) bool {
    // TODO: openssl treats more characters as printable.
    // crypto/ctype.c file.
    // TODO: golang (crypto/x509) allows also '*' and '&'.
    for (str) |char| {
        // Defined in ITU-T X.680 41.4.
        if (!(std.ascii.isAlphanumeric(char) or char == ' ' or char == '\'' or
            char == '(' or char == ')' or char == '+' or char == ',' or
            char == '-' or char == '.' or char == '/' or char == ':' or
            char == '=' or char == '?' or (allow_asterisk and char == '*'))) return false;
    }
    return true;
}

pub fn isValidNumericString(str: []const u8) bool {
    for (str) |char| {
        if (!(std.ascii.isDigit(char) or char == ' ')) return false;
    }
    return true;
}

pub const DirectoryString = union(enum) {
    // PrintableString, a valid printable ASCII string.
    printable: []const u8,

    // UTF8String, a valid utf8 string.
    utf8: []const u8,

    // T61String (also called TeletexString), ISO 8859-1 string.
    //
    // It should be encoded in a special T61 encoding, but many implementations (all?)
    // treat this as a ISO 8859-1:
    //
    // man openssl-x509:
    //  The conversion to UTF8 format used with the name options assumes that T61Strings use the ISO8859-1
    //  character set. This is wrong but Netscape and MSIE do this as do many certificates. So although this
    //  is incorrect it is more likely to print the majority of certificates correctly.
    // https://www.mail-archive.com/asn1@asn1.org/msg00460.html
    // https://github.com/dotnet/runtime/issues/25195
    // https://github.com/dotnet/corefx/pull/30572
    //
    // We are assuming that this is ISO 8859-1 (same as openssl, golang (TODO: CL))
    t61: []const u8,

    // BMPString, valid UTF-16 string (big-endian) with maximum U+FFFF unicode code point.
    //
    // It is string type that contains unicode
    // code points encoded in 2 byte integers (big-endian).
    // So basicaly it is UTF-16 but restricted to 2 bytes per character.
    bmp: []const u8,

    // UniversalString, valid UTF-32 string (big-endian).
    universal: []const u8,

    // charCount returns the number of characters in the string.
    pub fn charCount(self: DirectoryString) usize {
        switch (self) {
            .printable, .t61 => |str| return str.len,
            .utf8 => |str| return std.unicode.utf8CountCodepoints(str) catch unreachable,
            .bmp => |str| return str.len / 2,
            .universal => |str| return str.len / 4,
        }
    }

    pub fn freeUtf8(self: DirectoryString, allocator: std.mem.Allocator, utf8: []const u8) void {
        switch (self) {
            .printable, .utf8 => {},
            .t61 => |str| if (str.ptr != utf8.ptr) allocator.free(utf8),
            .bmp, .universal => allocator.free(utf8),
        }
    }

    // asUtf8 returns a valid UTF-8 representation of the DirectoryString
    // the returned slice might come from the DirectoryString or an allocated
    // memory from the allocator when the encoding in DirectoryString is not
    // utf8 compatible. Use freeUtf8 method to free this string.
    pub fn asUtf8(self: DirectoryString, allocator: std.mem.Allocator) ![]const u8 {
        switch (self) {
            .printable, .utf8 => |str| return str,
            .t61 => |str| {
                var utf8_bytes_count: usize = 0;
                for (str) |char| {
                    utf8_bytes_count += std.unicode.utf8CodepointSequenceLength(char) catch unreachable;
                }

                if (utf8_bytes_count == str.len) {
                    // This is valid ASCII, so no need to allocate memory.
                    return str;
                } else {
                    var out = try allocator.alloc(u8, utf8_bytes_count);
                    var out_offset: usize = 0;
                    for (str) |char| {
                        out_offset += std.unicode.utf8Encode(char, out[out_offset..]) catch unreachable;
                    }
                    return out;
                }
            },
            .bmp => |str| {
                // TODO: replace once this gets merged https://github.com/ziglang/zig/pull/15425
                var utf8_bytes_count: usize = 0;

                var i: usize = 0;
                while (i < str.len) : (i += 2) {
                    var iter = std.unicode.Utf16LeIterator.init(&[2]u16{ str[i + 1], str[i] });
                    const code_point = iter.nextCodepoint() catch unreachable orelse unreachable;
                    utf8_bytes_count += std.unicode.utf8CodepointSequenceLength(code_point) catch unreachable;
                }

                var out = try allocator.alloc(u8, utf8_bytes_count);

                i = 0;
                var out_offset: usize = 0;
                while (i < str.len) : (i += 2) {
                    var iter = std.unicode.Utf16LeIterator.init(&[2]u16{ str[i + 1], str[i] });
                    const code_point = iter.nextCodepoint() catch unreachable orelse unreachable;
                    out_offset += std.unicode.utf8Encode(code_point, out[out_offset..]) catch unreachable;
                }

                return out;
            },
            .universal => |str| {
                var utf8_bytes_count: usize = 0;

                var i: usize = 0;
                while (i < str.len) : (i += 4) {
                    const code_point = std.mem.readIntBig(u32, str[i..][0..4]);
                    utf8_bytes_count += std.unicode.utf8CodepointSequenceLength(@intCast(u21, code_point)) catch unreachable;
                }

                var out = try allocator.alloc(u8, utf8_bytes_count);
                var out_offset: usize = 0;
                i = 0;
                while (i < str.len) : (i += 4) {
                    const code_point = std.mem.readIntBig(u32, str[i..][0..4]);
                    out_offset += std.unicode.utf8Encode(@intCast(u21, code_point), out[out_offset..]) catch unreachable;
                }

                return out;
            },
        }
    }
};

pub const ParseDirectoryStringOptions = packed struct {
    allow_asterisk_in_printable_string: bool = false,
};

pub fn parseDirectoryString(el: DerDecoder.Element, opts: ?ParseDirectoryStringOptions) !DirectoryString {
    const o = if (opts) |p| p else ParseDirectoryStringOptions{
        .allow_asterisk_in_printable_string = true,
    };

    switch (el.tag) {
        19 => {
            if (!isValidPrintableString(el.data, o.allow_asterisk_in_printable_string)) return error.InvalidEncoding;
            return .{ .printable = el.data };
        },
        12 => {
            if (!std.unicode.utf8ValidateSlice(el.data)) return error.InvalidEncoding;
            return .{ .utf8 = el.data };
        },
        20 => return .{ .t61 = el.data },
        30 => {
            if (el.data.len % 2 != 0) return error.InvalidEncoding;

            // TODO: Currently zig doesn't have a Utf16BeIterator, replace this in future.
            // https://github.com/ziglang/zig/pull/15425
            var i: usize = 0;
            while (i < el.data.len) : (i += 2) {
                var iter = std.unicode.Utf16LeIterator.init(&[2]u16{ el.data[1], el.data[0] });
                if (iter.nextCodepoint() catch return error.InvalidEncoding) |code_point| {
                    if (!std.unicode.utf8ValidCodepoint(code_point) or code_point > 0xffff) return error.InvalidEncoding;
                } else return error.InvalidEncoding;
            }

            return .{ .bmp = el.data };
        },
        28 => {
            if (el.data.len % 4 != 0) return error.InvalidEncoding;

            var i: usize = 0;
            while (i < el.data.len) : (i += 4) {
                const code_point = std.mem.readIntBig(u32, el.data[i..][0..4]);
                if (code_point > std.math.maxInt(u21) or !std.unicode.utf8ValidCodepoint(@intCast(u21, code_point)))
                    return error.InvalidEncoding;
            }

            return .{ .universal = el.data };
        },
        else => return error.InvalidEncoding,
    }
}
