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
    pub const Integer = []const u8;
};

test {
    _ = Asn1;
    _ = Asn1.BitString;
}

pub const Ext = struct {
    oid: Asn1.RawObjectIdentifier,
    critical: bool,
    value: []const u8,

    pub const Extension = union(enum) {
        authority_key_identifier: AuthorityKeyIdentifier,
        subject_key_identifier: SubjectKeyIdentifier,
        key_usage: KeyUsage,
        subject_alt_name: SubjectAlternativeName,
        basic_constraints: BasicConstraints,
    };

    pub fn parse(ext: Ext) !?Extension {
        if (std.mem.eql(u8, ext.oid, AuthorityKeyIdentifier.OID)) {
            return .{ .authority_key_identifier = try AuthorityKeyIdentifier.parse(ext.value) };
        } else if (std.mem.eql(u8, ext.oid, SubjectKeyIdentifier.OID)) {
            return .{ .subject_key_identifier = try SubjectKeyIdentifier.parse(ext.value) };
        } else if (std.mem.eql(u8, ext.oid, KeyUsage.OID)) {
            return .{ .key_usage = try KeyUsage.parse(ext.value) };
        } else if (std.mem.eql(u8, ext.oid, SubjectAlternativeName.OID)) {
            return .{ .subject_alt_name = try SubjectAlternativeName.parse(ext.value) };
        } else if (std.mem.eql(u8, ext.oid, BasicConstraints.OID)) {
            return .{ .basic_constraints = try BasicConstraints.parse(ext.value) };
        } else return null;
    }

    pub const AuthorityKeyIdentifier = struct {
        const OID = Asn1.asRawObjectIdentifier(&[_]u64{ 2, 5, 29, 35 });

        key_identifier: ?[]const u8,

        pub fn parse(der: []const u8) !AuthorityKeyIdentifier {
            const sequence: u8 = 0x30;

            var decoder = DerDecoder{ .data = der };
            const seq_raw = try decoder.getElementWithTag(sequence);
            if (!decoder.empty()) return error.InvalidEncoding;

            var seq_decoder = DerDecoder{ .data = seq_raw };

            var key_identifier: ?[]const u8 = null;

            if (try seq_decoder.getOptionalElementWithTag(0b10000000)) |bytes| {
                key_identifier = bytes;
            }

            // not used fields
            // TODO: validate them acording to ASN.1
            if (try seq_decoder.getOptionalElementWithTag(0b10000001) != null) {
                if (try seq_decoder.getOptionalElementWithTag(0b10000010) == null)
                    return error.InvalidEncoding;
            }

            if (!seq_decoder.empty()) return error.InvalidEncoding;

            return .{ .key_identifier = key_identifier };
        }
    };

    pub const SubjectKeyIdentifier = struct {
        const OID = Asn1.asRawObjectIdentifier(&[_]u64{ 2, 5, 29, 14 });

        key_identifier: []const u8,

        pub fn parse(der: []const u8) !SubjectKeyIdentifier {
            const octetstring: u8 = 0x04;
            var decoder = DerDecoder{ .data = der };
            const key_identifier = try decoder.getElementWithTag(octetstring);
            if (!decoder.empty()) return error.InvalidEncoding;
            return .{ .key_identifier = key_identifier };
        }
    };

    pub const KeyUsage = packed struct {
        const OID = Asn1.asRawObjectIdentifier(&[_]u64{ 2, 5, 29, 15 });

        encipher_only: bool = false,
        crl_sig: bool = false,
        key_cert_sig: bool = false,
        key_agreement: bool = false,
        data_encipherment: bool = false,
        key_encipherment: bool = false,
        non_repudiation: bool = false,
        digital_signature: bool = false,
        decipher_only: bool = false,

        pub fn parse(der: []const u8) !KeyUsage {
            const bitstring: u8 = 0x03;

            var decoder = DerDecoder{ .data = der };
            const d = try decoder.getNamedBitStringWithTag(bitstring);
            if (!decoder.empty()) return error.InvalidEncoding;

            // ITU-T X.680:
            // 22.6 The presence of a "NamedBitList" has no effect on the set of abstract values of this type. Values containing
            // 1 bits other than the named bits are permitted.
            //
            // ITU-T X680 22.2:
            // The first bit in a bit string is called the leading bit. The final bit in a bit string is called the trailing bit.
            // NOTE – This terminology is used in specifying the value notation and in defining encoding rules.
            //
            // ITU-T X680 22.16
            // When using the "bstring" or "xmlbstring" notation, the leading bit of the bitstring value is on the left, and the
            // trailing bit of the bitstring value is on the right.
            //
            // ITU-T X680 22.4:
            // The value of each "number" or "DefinedValue" appearing in the "NamedBitList" shall be different, and is the
            // number of a distinguished bit in a bitstring value.
            // The leading bit of the bit string is identified by the "number" zero, with succeeding bits having successive values.
            var usage: u9 = 0;
            if (d.bytes.len > 0) usage |= @intCast(u9, d.bytes[0]);
            if (d.bytes.len > 1 and d.bytes[1] & 0x80 == 0x80) usage |= 256;
            return @bitCast(KeyUsage, usage);
        }

        test "parse" {
            try std.testing.expectEqual(
                KeyUsage{ .crl_sig = true, .key_cert_sig = true },
                try KeyUsage.parse(&[_]u8{ 0x03, 0x02, 0x01, 0b00000110 }),
            );
            try std.testing.expectEqual(@bitCast(KeyUsage, @intCast(u9, std.math.maxInt(u9))), try KeyUsage.parse(&[_]u8{ 0x03, 0x03, 0x07, 0xff, 0x80 }));

            try std.testing.expectEqual(KeyUsage{ .digital_signature = true }, try KeyUsage.parse(&[_]u8{ 0x03, 0x02, 0x07, 0b10000000 }));
            try std.testing.expectEqual(KeyUsage{ .non_repudiation = true }, try KeyUsage.parse(&[_]u8{ 0x03, 0x02, 0x06, 0b01000000 }));
            try std.testing.expectEqual(KeyUsage{ .key_encipherment = true }, try KeyUsage.parse(&[_]u8{ 0x03, 0x02, 0x05, 0b00100000 }));
            try std.testing.expectEqual(KeyUsage{ .data_encipherment = true }, try KeyUsage.parse(&[_]u8{ 0x03, 0x02, 0x04, 0b00010000 }));
            try std.testing.expectEqual(KeyUsage{ .key_agreement = true }, try KeyUsage.parse(&[_]u8{ 0x03, 0x02, 0x03, 0b00001000 }));
            try std.testing.expectEqual(KeyUsage{ .key_cert_sig = true }, try KeyUsage.parse(&[_]u8{ 0x03, 0x02, 0x02, 0b00000100 }));
            try std.testing.expectEqual(KeyUsage{ .crl_sig = true }, try KeyUsage.parse(&[_]u8{ 0x03, 0x02, 0x01, 0b00000010 }));
            try std.testing.expectEqual(KeyUsage{ .encipher_only = true }, try KeyUsage.parse(&[_]u8{ 0x03, 0x02, 0x00, 0b00000001 }));
            try std.testing.expectEqual(KeyUsage{ .decipher_only = true }, try KeyUsage.parse(&[_]u8{ 0x03, 0x03, 0x07, 0b00000000, 0b10000000 }));

            try std.testing.expectError(error.InvalidEncoding, KeyUsage.parse(&[_]u8{ 0x03, 0x03, 0x07, 0b00000000, 0b00000000 }));
            try std.testing.expectError(error.InvalidEncoding, KeyUsage.parse(&[_]u8{ 0x03, 0x03, 0x07, 0b00000000, 0b01000000 }));
            try std.testing.expectError(error.InvalidEncoding, KeyUsage.parse(&[_]u8{ 0x03, 0x03, 0x01, 0b00000000, 0b01000001 }));
            try std.testing.expectEqual(KeyUsage{}, try KeyUsage.parse(&[_]u8{ 0x03, 0x03, 0x06, 0b00000000, 0b01000000 }));
            try std.testing.expectEqual(@bitCast(KeyUsage, @intCast(u9, std.math.maxInt(u9))), try KeyUsage.parse(&[_]u8{ 0x03, 0x03, 0x00, 0xff, 0xff }));
        }
    };

    pub const SubjectAlternativeName = struct {
        const OID = Asn1.asRawObjectIdentifier(&[_]u64{ 2, 5, 29, 17 });

        raw: []const u8,

        pub const Iterator = struct {
            iter: RawIterator,

            pub fn next(self: *Iterator) ?GeneralName {
                while (self.iter.next()) |general_name| {
                    if (general_name.parse() catch unreachable) |parsed| {
                        return parsed;
                    }
                } else return null;
            }
        };

        pub fn iterator(self: SubjectAlternativeName) !Iterator {
            var iter = self.rawIterator();
            while (iter.next()) |general_name| {
                _ = try general_name.parse();
            }
            return .{ .iter = self.rawIterator() };
        }

        pub const RawIterator = struct {
            seq_decoder: DerDecoder,

            pub fn next(self: *RawIterator) ?RawGeneralName {
                if (self.seq_decoder.empty()) return null;
                const general_name = self.seq_decoder.getElement() catch unreachable;
                return .{ .raw = general_name };
            }
        };

        pub fn rawIterator(self: SubjectAlternativeName) RawIterator {
            return .{ .seq_decoder = DerDecoder{ .data = self.raw } };
        }

        // GeneralName contains a parsed general name.
        // The contents of each specific name is not validated in any way
        // to the rules specified by the x509 specs (i.e. the dns general name
        // might not be a valid dns name/hostname or the ip might not be a valid
        // IPv4/IPv6 binary address), only validations from ASN.1/DER are applied.
        //
        // It might be updated in future to containt more fields.
        pub const GeneralName = union(enum) {
            rfc822: []const u8,
            dns: []const u8,
            url: []const u8,
            ip: []const u8,

            // There are few unimplemented and The ITU-T X509 spec defines a general name
            // with (...) at the end, so it might containt more fields in future, but the RFC 5280 does not.
            _,
        };

        pub const RawGeneralName = struct {
            raw: DerDecoder.Element,

            pub fn parse(self: RawGeneralName) !?GeneralName {
                const context_specific = 0b10000000;

                switch (self.raw.tag) {
                    context_specific | 0x1 => {
                        if (!isAscii(self.raw.data)) return error.InvalidEncoding;
                        return .{ .rfc822 = self.raw.data };
                    },
                    context_specific | 0x2 => {
                        if (!isAscii(self.raw.data)) return error.InvalidEncoding;
                        return .{ .dns = self.raw.data };
                    },
                    context_specific | 0x6 => {
                        if (!isAscii(self.raw.data)) return error.InvalidEncoding;
                        return .{ .url = self.raw.data };
                    },
                    context_specific | 0x7 => return .{ .ip = self.raw.data },
                    else => return null,
                }
            }
        };

        pub fn parse(der: []const u8) !SubjectAlternativeName {
            const sequence: u8 = 0x30;

            var decoder = DerDecoder{ .data = der };
            const seq_raw = try decoder.getElementWithTag(sequence);
            if (!decoder.empty()) return error.InvalidEncoding;

            var seq_decoder = DerDecoder{ .data = seq_raw };
            if (seq_decoder.empty()) return error.InvalidEncoding;

            while (!seq_decoder.empty()) {
                _ = try seq_decoder.getElement();
            }

            return .{ .raw = seq_raw };
        }

        test "SubjectAlternativeName" {
            const sequence: u8 = 0x30;

            const der_general_name_unknown = &[_]u8{ 0xff, 11 } ++ "example.com";

            var san = DerBuilder{ .list = std.ArrayList(u8).init(std.testing.allocator) };
            defer san.deinit();

            const p = try san.newPrefixed(sequence);

            const ipv4_raw = [4]u8{ 192, 0, 2, 1 };
            const ip6 = try std.net.Ip6Address.parse("2001:db8::1", 0);
            const ipv6_raw = ip6.sa.addr;

            var c = try san.newPrefixed(0b10000001);
            try san.list.appendSlice("postmaster@example.com");
            try san.endPrefixed(c);

            c = try san.newPrefixed(0b10000010);
            try san.list.appendSlice("example.com");
            try san.endPrefixed(c);

            c = try san.newPrefixed(0b10000110);
            try san.list.appendSlice("https://example.com");
            try san.endPrefixed(c);

            c = try san.newPrefixed(0b10000111);
            try san.list.appendSlice(&ipv4_raw);
            try san.endPrefixed(c);

            c = try san.newPrefixed(0b10000111);
            try san.list.appendSlice(&ipv6_raw);
            try san.endPrefixed(c);

            try san.list.appendSlice(der_general_name_unknown);

            try san.endPrefixed(p);

            const sans_der = san.list.items;
            const san_ext = try SubjectAlternativeName.parse(sans_der);

            var iter = san_ext.rawIterator();
            try std.testing.expectEqualDeep(@as(?GeneralName, GeneralName{ .rfc822 = "postmaster@example.com" }), try iter.next().?.parse());
            try std.testing.expectEqualDeep(@as(?GeneralName, GeneralName{ .dns = "example.com" }), try iter.next().?.parse());
            try std.testing.expectEqualDeep(@as(?GeneralName, GeneralName{ .url = "https://example.com" }), try iter.next().?.parse());
            try std.testing.expectEqualDeep(@as(?GeneralName, GeneralName{ .ip = &ipv4_raw }), try iter.next().?.parse());
            try std.testing.expectEqualDeep(@as(?GeneralName, GeneralName{ .ip = &ipv6_raw }), try iter.next().?.parse());

            const unknown_raw = iter.next().?;
            try std.testing.expectEqual(@as(?GeneralName, null), try unknown_raw.parse());
            try std.testing.expectEqualDeep(
                @as(?RawGeneralName, RawGeneralName{
                    .raw = .{
                        .tag = der_general_name_unknown[0],
                        .data = der_general_name_unknown[2..],
                    },
                }),
                unknown_raw,
            );

            try std.testing.expectEqual(@as(?RawGeneralName, null), iter.next());
            try std.testing.expectEqual(@as(?RawGeneralName, null), iter.next());

            var parsed_iter = try san_ext.iterator();
            try std.testing.expectEqualDeep(@as(?GeneralName, GeneralName{ .rfc822 = "postmaster@example.com" }), parsed_iter.next());
            try std.testing.expectEqualDeep(@as(?GeneralName, GeneralName{ .dns = "example.com" }), parsed_iter.next());
            try std.testing.expectEqualDeep(@as(?GeneralName, GeneralName{ .url = "https://example.com" }), parsed_iter.next());
            try std.testing.expectEqualDeep(@as(?GeneralName, GeneralName{ .ip = &ipv4_raw }), parsed_iter.next());
            try std.testing.expectEqualDeep(@as(?GeneralName, GeneralName{ .ip = &ipv6_raw }), parsed_iter.next());
            try std.testing.expectEqual(@as(?GeneralName, null), parsed_iter.next());
            try std.testing.expectEqual(@as(?GeneralName, null), parsed_iter.next());
        }
    };

    pub const BasicConstraints = struct {
        const OID = Asn1.asRawObjectIdentifier(&[_]u64{ 2, 5, 29, 19 });

        ca: bool,
        max_path_length: ?Asn1.Integer = null,

        pub fn parse(der: []const u8) !BasicConstraints {
            const boolean = 0x01;
            const sequence: u8 = 0x30;

            var decoder = DerDecoder{ .data = der };
            var seq_decoder = DerDecoder{ .data = try decoder.getElementWithTag(sequence) };
            if (!decoder.empty()) return error.InvalidEncoding;

            const ca = try seq_decoder.getBooleanWithDefaultWithTag(false, boolean);
            const max_path_length = try seq_decoder.getOptionalIntegerBytesWithTag(0x02);
            if (max_path_length) |m| {
                if (m[0] & 0x80 != 0) return error.InvalidEncoding;
            }

            if (!seq_decoder.empty()) return error.InvalidEncoding;
            return .{
                .ca = ca,
                .max_path_length = max_path_length,
            };
        }
    };
};

fn isAscii(str: []const u8) bool {
    for (str) |char| {
        if (!std.ascii.isASCII(char)) return false;
    }
    return true;
}

fn isValidPrintableString(str: []const u8, allow_asterisk: bool) bool {
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

const ParseDirectoryStringOptions = packed struct {
    allow_asterisk_in_printable_string: bool = false,
};

fn parseDirectoryString(el: DerDecoder.Element, opts: ?ParseDirectoryStringOptions) !DirectoryString {
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

pub const Name = struct {
    raw: []const u8,

    pub const Entry = union(enum) {
        common_name: DirectoryString,
        serial_number: []const u8,
        country: []const u8,
        province: DirectoryString,
        organization: DirectoryString,
        organizational_unit: DirectoryString,
    };

    const oid_common_name = Asn1.asRawObjectIdentifier(&[_]u64{ 2, 5, 4, 3 });
    const oid_serial_number = Asn1.asRawObjectIdentifier(&[_]u64{ 2, 5, 4, 5 });
    const oid_country = Asn1.asRawObjectIdentifier(&[_]u64{ 2, 5, 4, 6 });
    const oid_state_or_province = Asn1.asRawObjectIdentifier(&[_]u64{ 2, 5, 4, 8 });
    const oid_organization = Asn1.asRawObjectIdentifier(&[_]u64{ 2, 5, 4, 10 });
    const oid_organizational_unit = Asn1.asRawObjectIdentifier(&[_]u64{ 2, 5, 4, 11 });

    pub const Iterator = struct {
        raw_iterator: RawIterator,

        pub fn next(self: *Iterator) ?Entry {
            while (self.raw_iterator.next()) |atav| {
                if (atav.parse() catch unreachable) |parsed| {
                    return parsed;
                }
            }
            return null;
        }
    };

    pub fn iterator(self: Name) !Iterator {
        var iter = self.rawIterator();
        while (iter.next()) |atav| _ = try atav.parse();
        return .{ .raw_iterator = self.rawIterator() };
    }

    pub const RawIterator = struct {
        rdn_sequence: DerDecoder,
        rdn_set: DerDecoder,

        pub fn next(self: *RawIterator) ?AttributeTypeAndValue {
            const oid = 0x06;
            const set: u8 = 0x31;
            const sequence: u8 = 0x30;

            if (self.rdn_set.empty()) {
                if (self.rdn_sequence.empty()) return null;
                self.rdn_set = DerDecoder{ .data = self.rdn_sequence.getElementWithTag(set) catch unreachable };
            }

            var rdn_set = &self.rdn_set;
            var atav = DerDecoder{ .data = rdn_set.getElementWithTag(sequence) catch unreachable };

            return .{
                .oid = atav.getRawObjectIdentifierWithTag(oid) catch unreachable,
                .value = atav.getElement() catch unreachable,
            };
        }
    };

    pub fn rawIterator(self: Name) RawIterator {
        return .{ .rdn_sequence = DerDecoder{ .data = self.raw }, .rdn_set = DerDecoder{ .data = &[_]u8{} } };
    }

    pub const AttributeTypeAndValue = struct {
        oid: Asn1.RawObjectIdentifier,
        value: DerDecoder.Element,

        pub fn parse(self: AttributeTypeAndValue) !?Entry {
            if (std.mem.eql(u8, oid_common_name, self.oid)) {
                return .{ .common_name = try parseDirectoryStringWithSizeConstraint(self.value, 1, 64) };
            } else if (std.mem.eql(u8, oid_serial_number, self.oid)) {
                if (self.value.tag != 19) return error.InvalidEncoding;
                if (self.value.data.len == 0) return error.InvalidEncoding;
                if (self.value.data.len > 64) return error.InvalidEncoding;
                if (!isValidPrintableString(self.value.data, false)) return error.InvalidEncoding;
                return .{ .serial_number = self.value.data };
            } else if (std.mem.eql(u8, oid_country, self.oid)) {
                if (self.value.tag != 19) return error.InvalidEncoding;
                if (self.value.data.len != 2) return error.InvalidEncoding;
                if (!isValidPrintableString(self.value.data, false)) return error.InvalidEncoding;
                return .{ .country = self.value.data };
            } else if (std.mem.eql(u8, oid_state_or_province, self.oid)) {
                return .{ .province = try parseDirectoryStringWithSizeConstraint(self.value, 1, 128) };
            } else if (std.mem.eql(u8, oid_organization, self.oid)) {
                return .{ .organization = try parseDirectoryStringWithSizeConstraint(self.value, 1, 64) };
            } else if (std.mem.eql(u8, oid_organizational_unit, self.oid)) {
                return .{ .organizational_unit = try parseDirectoryStringWithSizeConstraint(self.value, 1, 64) };
            } else return null;
        }

        fn parseDirectoryStringWithSizeConstraint(el: DerDecoder.Element, min: usize, max: usize) !DirectoryString {
            const d = try parseDirectoryString(el, null);
            const chars = d.charCount();
            if (chars < min) return error.InvalidEncoding;
            if (chars > max) return error.InvalidEncoding;
            return d;
        }
    };

    pub fn parse(der: []const u8) !Name {
        const set: u8 = 0x31;
        const sequence: u8 = 0x30;
        const oid = 0x06;

        var rdn_sequence = DerDecoder{ .data = der };

        while (!rdn_sequence.empty()) {
            var relative_distinguished_name_set = DerDecoder{ .data = try rdn_sequence.getElementWithTag(set) };
            if (relative_distinguished_name_set.empty()) return error.InvalidEncoding;

            while (!relative_distinguished_name_set.empty()) {
                var attribute_type_and_value_seq = DerDecoder{ .data = try relative_distinguished_name_set.getElementWithTag(sequence) };
                _ = try attribute_type_and_value_seq.getRawObjectIdentifierWithTag(oid);
                _ = try attribute_type_and_value_seq.getElement();
                if (!attribute_type_and_value_seq.empty()) return error.InvalidEncoding;
            }
        }

        return .{ .raw = der };
    }

    test "parse" {
        const cn = "ROOT-CA";

        const der = try testBuildName(
            std.testing.allocator,
            &[_]AttributeTypeAndValue{
                .{ .oid = oid_common_name, .value = .{ .tag = 19, .data = cn } },
                .{ .oid = oid_common_name, .value = .{ .tag = 12, .data = cn } },
                .{ .oid = oid_common_name, .value = .{ .tag = 30, .data = &asUtf16BE(cn) } },
                .{ .oid = oid_common_name, .value = .{ .tag = 28, .data = &asUtf32BE(cn) } },
            },
        );
        defer std.testing.allocator.free(der);

        const name = try parse(der);
        var iter = try name.iterator();

        {
            const entry = iter.next();
            try std.testing.expectEqualDeep(@as(?Entry, Entry{ .common_name = .{ .printable = cn } }), entry);
            try testExpectDirectoryString(entry.?.common_name, cn);
        }
        {
            const entry = iter.next();
            try std.testing.expectEqualDeep(@as(?Entry, Entry{ .common_name = .{ .utf8 = cn } }), entry);
            try testExpectDirectoryString(entry.?.common_name, cn);
        }
        {
            const entry = iter.next();
            try std.testing.expectEqualDeep(@as(?Entry, Entry{ .common_name = .{ .bmp = &asUtf16BE(cn) } }), entry);
            try testExpectDirectoryString(entry.?.common_name, cn);
        }
        {
            const entry = iter.next();
            try std.testing.expectEqualDeep(@as(?Entry, Entry{ .common_name = .{ .universal = &asUtf32BE(cn) } }), entry);
            try testExpectDirectoryString(entry.?.common_name, cn);
        }

        try std.testing.expectEqualDeep(@as(?Entry, null), iter.next());
        try std.testing.expectEqualDeep(@as(?Entry, null), iter.next());
    }

    fn testExpectDirectoryString(str: DirectoryString, expect: []const u8) !void {
        var cn_utf8 = try str.asUtf8(std.testing.allocator);
        defer str.freeUtf8(std.testing.allocator, cn_utf8);
        try std.testing.expectEqualStrings(expect, cn_utf8);
        try std.testing.expectEqual(expect.len, str.charCount());
    }

    fn testBuildName(allocator: std.mem.Allocator, atavs: []const AttributeTypeAndValue) ![]const u8 {
        const set: u8 = 0x31;
        const sequence: u8 = 0x30;

        var b = DerBuilder{ .list = std.ArrayList(u8).init(allocator) };
        errdefer b.deinit();

        for (atavs) |atav| {
            var rdns = try b.newPrefixed(set);
            var seq = try b.newPrefixed(sequence);
            {
                try b.appendOID(atav.oid);
                var val = try b.newPrefixed(atav.value.tag);
                try b.list.appendSlice(atav.value.data);
                try b.endPrefixed(val);
            }
            try b.endPrefixed(seq);
            try b.endPrefixed(rdns);
        }

        return b.list.toOwnedSlice();
    }

    fn asUtf16BE(comptime utf8: []const u8) [2 * (std.unicode.calcUtf16LeLen(utf8) catch unreachable)]u8 {
        const utf16le = comptime std.unicode.utf8ToUtf16LeStringLiteral(utf8);
        var ret: [utf16le.len * 2]u8 = undefined;
        inline for (utf16le, 0..) |c, i| {
            std.mem.writeIntSliceBig(u16, ret[i * 2 .. i * 2 + 2], c);
        }
        return ret;
    }

    fn asUtf32BE(comptime utf8: []const u8) [(std.unicode.utf8CountCodepoints(utf8) catch unreachable) * 4]u8 {
        var ret: [(std.unicode.utf8CountCodepoints(utf8) catch unreachable) * 4]u8 = undefined;
        var iter = std.unicode.Utf8Iterator{ .bytes = utf8, .i = 0 };
        var out_offset: usize = 0;
        while (iter.nextCodepoint()) |cp| {
            std.mem.writeIntSliceBig(u32, ret[out_offset .. out_offset + 4], cp);
            out_offset += 4;
        }
        return ret;
    }
};

const Certificate = struct {
    raw: []const u8,
    raw_tbs_certificate: []const u8,

    version: Version,
    serial_number: Asn1.Integer,
    signature_algorithm_identifier: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicInfo,
    exts: ?Exts,

    signature_algorithm: AlgorithmIdentifier,
    signature: Asn1.BitString,

    pub const Version = enum { v1, v2, v3 };

    pub const AlgorithmIdentifier = struct {
        algorithm: Asn1.RawObjectIdentifier,
        paramters: ?[]const u8,
    };

    pub const Validity = struct {
        not_before: i64,
        not_after: i64,

        pub fn isValid(self: Validity, now_utc: i64) bool {
            if (now_utc < self.not_before) return false;
            if (now_utc > self.not_after) return false;
            return true;
        }
    };

    pub const SubjectPublicInfo = struct {
        algorithm: AlgorithmIdentifier,
        public_key: Asn1.BitString,
    };

    pub const Exts = struct {
        raw: []const u8,

        pub fn getExtByOid(self: Exts, oid: Asn1.RawObjectIdentifier) ?Ext {
            var iter = self.iterator();
            while (iter.next()) |ext| {
                if (std.mem.eql(u8, ext.oid, oid)) {
                    return ext;
                }
            }
            return null;
        }

        pub const Iterator = struct {
            decoder: DerDecoder,

            pub fn next(self: *Iterator) ?Ext {
                const sequence: u8 = 0x30;
                const oid = 0x06;
                const octetstring: u8 = 0x04;
                const boolean = 0x01;

                if (self.decoder.empty()) return null;

                var ext = DerDecoder{ .data = self.decoder.getElementWithTag(sequence) catch unreachable };
                return .{
                    .oid = ext.getElementWithTag(oid) catch unreachable,
                    .critical = ext.getBooleanWithDefaultWithTag(false, boolean) catch unreachable,
                    .value = ext.getElementWithTag(octetstring) catch unreachable,
                };
            }
        };

        pub fn iterator(self: Exts) Iterator {
            return .{ .decoder = .{ .data = self.raw } };
        }
    };

    pub const Error = error{
        InvalidEncoding,
        UnsupportedVersion,
    } || std.mem.Allocator.Error;

    // parse parses a der encoded X509 certificate.
    // Fields in the returned Certificate share memory with the provided der slice.
    // allocator is used only for internal processing, no need to deinit a parsed certificate.
    pub fn parse(allocator: std.mem.Allocator, der: []const u8) Error!Certificate {
        const sequence: u8 = 0x30;
        const octetstring: u8 = 0x04;
        const oid = 0x06;
        const bitstring: u8 = 0x03;
        const boolean = 0x01;
        const integer = 0x02;

        var decoder = DerDecoder{ .data = der };
        var certificate = DerDecoder{ .data = try decoder.getElementWithTag(sequence) };
        if (!decoder.empty()) return error.InvalidEncoding;

        const tbs_certificate_raw = try certificate.getElementWithTag(sequence);
        var tbs_certificate = DerDecoder{ .data = tbs_certificate_raw };

        const version: Version = if (try tbs_certificate.getOptionalElementWithTag(0xA0)) |version_explicit_bytes| blk: {
            var version_explicit = DerDecoder{ .data = version_explicit_bytes };
            const version_bytes = try version_explicit.getIntegerBytesWithTag(integer);
            if (!version_explicit.empty()) return error.InvalidEncoding;

            if (version_bytes.len == 1) {
                break :blk if (version_bytes[0] == 0)
                    // As per DER, default values are not encoded.
                    return error.InvalidEncoding
                else if (version_bytes[0] == 1)
                    .v2
                else if (version_bytes[0] == 2)
                    .v3
                else
                    return error.UnsupportedVersion;
            } else return error.UnsupportedVersion;
        } else .v1;

        // RFC 5280 4.1.2.2. Serial Number:
        // The serial number MUST be a positive integer assigned by the CA to
        // each certificate.
        // CAs MUST force the serialNumber to be a non-negative integer.
        // Note: Non-conforming CAs may issue certificates with serial numbers
        // that are negative or zero.  Certificate users SHOULD be prepared to
        // gracefully handle such certificates.
        const serial_number = try tbs_certificate.getIntegerBytesWithTag(0x02);

        const signature_algorithm_identifier = try parseAlgorithmIdentifier(try tbs_certificate.getElementWithTag(sequence));

        const issuer = try Name.parse(try tbs_certificate.getElementWithTag(sequence));
        // 4.1.2.4.  The issuer field MUST contain a non-empty distinguished name (DN).
        var itr = issuer.rawIterator();
        if (itr.next() == null) return error.InvalidEncoding;

        const validity = try parseValidity(try tbs_certificate.getElementWithTag(sequence));
        const subject = try Name.parse(try tbs_certificate.getElementWithTag(sequence));

        var subject_public_key_info_seq = DerDecoder{ .data = try tbs_certificate.getElementWithTag(sequence) };
        const subject_public_key_info = SubjectPublicInfo{
            .algorithm = try parseAlgorithmIdentifier(try subject_public_key_info_seq.getRawObjectIdentifierWithTag(sequence)),
            .public_key = try subject_public_key_info_seq.getBitStringWithTag(bitstring),
        };
        if (!subject_public_key_info_seq.empty()) return error.InvalidEncoding;

        if (version == .v2 or version == .v3) {
            // Skip issuerUniqueID, subjectUniqueID they are unused.
            const issuer_unique_id_tag = 0b10000000 | 1;
            const subject_unique_id_tag = 0b10000000 | 2;
            _ = try tbs_certificate.getOptionalBitStringWithTag(issuer_unique_id_tag);
            _ = try tbs_certificate.getOptionalBitStringWithTag(subject_unique_id_tag);
        }

        var exts: ?Exts = null;

        if (version == .v3) {
            const extensions_tag = 0b10100000 | 3;
            if (try tbs_certificate.getOptionalElementWithTag(extensions_tag)) |e| {
                var map = std.StringHashMap(void).init(allocator);
                defer map.deinit();

                var exts_seq_decoder = DerDecoder{ .data = e };
                const exts_data = try exts_seq_decoder.getElementWithTag(sequence);
                if (!exts_seq_decoder.empty()) return error.InvalidEncoding;
                var exts_decoder = DerDecoder{ .data = exts_data };
                exts = .{ .raw = exts_data };

                if (exts_decoder.empty()) return error.InvalidEncoding;

                while (!exts_decoder.empty()) {
                    var extension_decoder = DerDecoder{ .data = try exts_decoder.getElementWithTag(sequence) };
                    const raw_oid = try extension_decoder.getRawObjectIdentifierWithTag(oid);
                    _ = try extension_decoder.getBooleanWithDefaultWithTag(false, boolean);
                    _ = try extension_decoder.getElementWithTag(octetstring);
                    if (!extension_decoder.empty()) return error.InvalidEncoding;

                    // Detect duplicate extension.
                    if (map.get(raw_oid)) |_| return error.InvalidEncoding;
                    try map.put(raw_oid, {});
                }
            }
        }

        if (!tbs_certificate.empty()) return error.InvalidEncoding;

        const signature_algorithm = try parseAlgorithmIdentifier(try certificate.getElementWithTag(sequence));

        // RFC 5280 4.1.1.2. signatureAlgorithm:
        // This field MUST contain the same algorithm identifier as the
        // signature field in the sequence tbsCertificate (Section 4.1.2.3).
        if (!std.mem.eql(u8, signature_algorithm.algorithm, signature_algorithm_identifier.algorithm)) return error.InvalidEncoding;
        if (signature_algorithm.paramters == null or signature_algorithm_identifier.paramters == null) {
            if (!(signature_algorithm.paramters == null and signature_algorithm_identifier.paramters == null)) return error.InvalidEncoding;
        } else {
            if (!std.mem.eql(u8, signature_algorithm.paramters.?, signature_algorithm_identifier.paramters.?)) return error.InvalidEncoding;
        }

        const signature = try certificate.getBitStringWithTag(bitstring);

        if (!certificate.empty()) return error.InvalidEncoding;

        // TODO:
        // X509: 7.2 Public-key certificate:
        // If the public-key certificate is for an end-entity, then the
        // distinguished name may be an empty sequence providing that the subjectAltName extension is present and is flagged
        // as critical. Otherwise, it shall be a non-empty distinguished name (see clause 8.3.2.1).

        if (exts) |extensions| {
            var ext_iter = extensions.iterator();
            while (ext_iter.next()) |ext| {
                _ = try ext.parse();
            }
        }

        return .{
            .raw = der,
            .raw_tbs_certificate = tbs_certificate_raw,

            .version = version,
            .serial_number = serial_number,
            .signature_algorithm_identifier = signature_algorithm_identifier,
            .issuer = issuer,
            .validity = validity,
            .subject = subject,
            .subject_public_key_info = subject_public_key_info,
            .exts = exts,

            .signature_algorithm = signature_algorithm,
            .signature = signature,
        };
    }

    fn parseAlgorithmIdentifier(seq: []const u8) !AlgorithmIdentifier {
        const oid = 0x06;

        var algorithm_identifer_seq = DerDecoder{ .data = seq };
        return .{
            .algorithm = try algorithm_identifer_seq.getElementWithTag(oid),
            .paramters = blk: {
                if (algorithm_identifer_seq.empty()) break :blk null;
                const raw = algorithm_identifer_seq.data;
                _ = try algorithm_identifer_seq.getElement();
                if (!algorithm_identifer_seq.empty()) return error.InvalidEncoding;
                break :blk raw;
            },
        };
    }

    fn parseValidity(seq: []const u8) !Validity {
        var validity_seq = DerDecoder{ .data = seq };

        const utc_time = 23;
        const generalized_time = 24;

        const not_before = try validity_seq.getElement();
        const not_after = try validity_seq.getElement();
        if (!validity_seq.empty()) return error.InvalidEncoding;

        return .{
            .not_before = switch (not_before.tag) {
                utc_time => try parseUTCTime(not_before.data),
                generalized_time => try parseGeneralizedTime(not_before.data),
                else => return error.InvalidEncoding,
            },
            .not_after = switch (not_after.tag) {
                utc_time => try parseUTCTime(not_after.data),
                generalized_time => try parseGeneralizedTime(not_after.data),
                else => return error.InvalidEncoding,
            },
        };
    }

    fn parseInteger(in: [2]u8, min_value: u8, max_value: u8) !u8 {
        if (!std.ascii.isDigit(in[0]) or !std.ascii.isDigit(in[1])) return error.InvalidEncoding;
        const val = ((in[0] - '0') * 10) + in[1] - '0';
        if (val > max_value or val < min_value) return error.InvalidEncoding;
        return val;
    }

    fn parseIntegerFrom4(in: [4]u8) !u16 {
        if (!std.ascii.isDigit(in[0]) or !std.ascii.isDigit(in[1]) or !std.ascii.isDigit(in[2]) or !std.ascii.isDigit(in[3])) return error.InvalidEncoding;
        return (@intCast(u16, in[0] - '0') * 1000) + (@intCast(u16, in[1] - '0') * 100) + ((in[2] - '0') * 10) + in[3] - '0';
    }

    fn parseUTCTime(date: []const u8) !i64 {
        const format = "YYMMDDHHMMSSZ";
        if (date.len != format.len) return error.InvalidEncoding;
        if (date[date.len - 1] != 'Z') return error.InvalidEncoding;

        const year = try parseInteger(date[0..2].*, 0, 99);
        const month = try parseInteger(date[2..4].*, 1, 12);
        const day = try parseInteger(date[4..6].*, 1, 31);
        const hour = try parseInteger(date[6..8].*, 0, 23);
        const minute = try parseInteger(date[8..10].*, 0, 59);
        const second = try parseInteger(date[10..12].*, 0, 59);

        // Conforming systems MUST interpret the year field (YY) as follows:
        //
        // Where YY is greater than or equal to 50, the year SHALL be
        // interpreted as 19YY; and
        //
        // Where YY is less than 50, the year SHALL be interpreted as 20YY.
        const real_year: u16 = if (year >= 50) 1900 + @intCast(u16, year) else 2000 + @intCast(u16, year);

        return dateToUnixTimestamp(real_year, month, day, hour, minute, second);
    }

    fn parseGeneralizedTime(date: []const u8) !i64 {
        const format = "YYYYMMDDHHMMSSZ";
        if (date.len != format.len) return error.InvalidEncoding;
        if (date[date.len - 1] != 'Z') return error.InvalidEncoding;

        const year = try parseIntegerFrom4(date[0..4].*);
        const month = try parseInteger(date[4..6].*, 1, 12);
        const day = try parseInteger(date[6..8].*, 1, 31);
        const hour = try parseInteger(date[8..10].*, 0, 23);
        const minute = try parseInteger(date[10..12].*, 0, 59);
        const second = try parseInteger(date[12..14].*, 0, 59);

        return dateToUnixTimestamp(year, month, day, hour, minute, second);
    }

    fn dateToUnixTimestamp(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) !i64 {
        var sec: i64 = getUnixTimestampStartOfYear(year);

        const year_type: std.time.epoch.YearLeapKind = if (std.time.epoch.isLeapYear(year)) .leap else .not_leap;
        const m = @intToEnum(std.time.epoch.Month, @truncate(u5, month));
        const days = std.time.epoch.getDaysInMonth(year_type, m);
        if (day > days) return error.InvalidEncoding;

        sec += @intCast(i64, getDaysOfYearTillMonth(year_type, m)) * 24 * 60 * 60;
        sec += @intCast(i64, day - 1) * 24 * 60 * 60;
        sec += @intCast(i64, hour) * 60 * 60;
        sec += @intCast(i64, minute) * 60;
        sec += @intCast(i64, second);
        return sec;
    }

    // getUnixTimestampStartOfYear returns the unix timestamp of
    // january first at 00:00:00 of the year.
    fn getUnixTimestampStartOfYear(year: u16) i64 {
        const epoch_year = std.time.epoch.epoch_year;
        if (year == 0) {
            // There isn't a year 0, but it is intepreted as -1 year, as in ISO 8601.
            // Note: -1 is also an leap year.
            // Predefined value, because leapYearsBetween, does not work for start == 0
            return -62167219200;
        } else if (year > epoch_year) {
            const days: i64 = @intCast(i64, year - epoch_year) * 365 + leapYearsBetween(epoch_year, year);
            return days * 24 * 60 * 60;
        } else if (year < epoch_year) {
            const days: i64 = @intCast(i64, @intCast(i64, year) - @intCast(i64, epoch_year)) * 365 - leapYearsBetween(year, epoch_year);
            return days * 24 * 60 * 60;
        } else {
            return 0;
        }
    }

    test "getUnixTimestampStartOfYear" {
        const year = 365 * 24 * 60 * 60;
        const leap_year = 366 * 24 * 60 * 60;

        try std.testing.expectEqual(getUnixTimestampStartOfYear(1963), -(5 * year + 2 * leap_year));
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1964), -(4 * year + 2 * leap_year));
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1965), -(4 * year + leap_year));
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1966), -(3 * year + leap_year));
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1967), -(2 * year + leap_year));
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1968), -(year + leap_year));
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1969), -year);
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1970), 0);
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1971), year);
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1972), 2 * year);
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1973), 2 * year + leap_year);
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1974), 3 * year + leap_year);
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1975), 4 * year + leap_year);
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1976), 5 * year + leap_year);
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1977), 5 * year + 2 * leap_year);

        // Values cauculated using golang: fmt.Println(time.Date(1234, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
        try std.testing.expectEqual(getUnixTimestampStartOfYear(9999), 253370764800);
        try std.testing.expectEqual(getUnixTimestampStartOfYear(2020), 1577836800);
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1567), -12717475200);
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1567), -12717475200);
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1000), -30610224000);
        try std.testing.expectEqual(getUnixTimestampStartOfYear(100), -59011459200);
        try std.testing.expectEqual(getUnixTimestampStartOfYear(1), -62135596800);
        try std.testing.expectEqual(getUnixTimestampStartOfYear(0), -62135596800 - leap_year);
        try std.testing.expectEqual(getUnixTimestampStartOfYear(0), -62167219200);
    }

    // leapYearsBetween returns the number of leap years between start (inclusive) and end (exclusive).
    fn leapYearsBetween(start: u16, end: u16) u16 {
        std.debug.assert(end > start);
        const e = end - 1;
        const s = start - 1;
        return ((e / 4) - (e / 100) + (e / 400)) - ((s / 4) - (s / 100) + (s / 400));
    }

    test "leapYearsBetween" {
        try std.testing.expectEqual(@intCast(u16, 2), leapYearsBetween(1963, 1970));
        try std.testing.expectEqual(@intCast(u16, 2), leapYearsBetween(1964, 1970));
        try std.testing.expectEqual(@intCast(u16, 1), leapYearsBetween(1965, 1970));
        try std.testing.expectEqual(@intCast(u16, 1), leapYearsBetween(1966, 1970));
        try std.testing.expectEqual(@intCast(u16, 1), leapYearsBetween(1967, 1970));
        try std.testing.expectEqual(@intCast(u16, 1), leapYearsBetween(1968, 1970));
        try std.testing.expectEqual(@intCast(u16, 0), leapYearsBetween(1969, 1970));
        try std.testing.expectEqual(@intCast(u16, 0), leapYearsBetween(1970, 1971));
        try std.testing.expectEqual(@intCast(u16, 0), leapYearsBetween(1970, 1972));
        try std.testing.expectEqual(@intCast(u16, 1), leapYearsBetween(1970, 1973));
        try std.testing.expectEqual(@intCast(u16, 1), leapYearsBetween(1970, 1974));
        try std.testing.expectEqual(@intCast(u16, 1), leapYearsBetween(1970, 1975));
        try std.testing.expectEqual(@intCast(u16, 1), leapYearsBetween(1970, 1976));
        try std.testing.expectEqual(@intCast(u16, 2), leapYearsBetween(1970, 1977));
        try std.testing.expectEqual(@intCast(u16, 2), leapYearsBetween(1970, 1977));

        for (1..1970) |start| {
            var leap_years: u16 = 0;
            for (start..1970) |y| {
                if (std.time.epoch.isLeapYear(@intCast(u16, y))) leap_years += 1;
            }
            try std.testing.expectEqual(leap_years, leapYearsBetween(@intCast(u16, start), 1970));
        }
        for (1971..10000) |end| {
            var leap_years: u16 = 0;
            for (1970..end) |y| {
                if (std.time.epoch.isLeapYear(@intCast(u16, y))) leap_years += 1;
            }
            try std.testing.expectEqual(leap_years, leapYearsBetween(1970, @intCast(u16, end)));
        }
    }

    // getDaysOfYearTillMonth returns number of days between the start of the year to the start of the month.
    fn getDaysOfYearTillMonth(leap: std.time.epoch.YearLeapKind, month: std.time.epoch.Month) u16 {
        return switch (leap) {
            inline else => |l| switch (month) {
                inline else => |mn| comptime blk: {
                    var count: u16 = 0;

                    var m = @enumToInt(mn);
                    inline while (m > 1) : (m -= 1) {
                        count += std.time.epoch.getDaysInMonth(l, @intToEnum(std.time.epoch.Month, m));
                    }

                    break :blk count;
                },
            },
        };
    }

    test "parse" {
        const cert_base64 =
            \\MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
            \\TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
            \\cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
            \\WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
            \\ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
            \\MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
            \\h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
            \\0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
            \\A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
            \\T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
            \\B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
            \\B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
            \\KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
            \\OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
            \\jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
            \\qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
            \\rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
            \\HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
            \\hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
            \\ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
            \\3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
            \\NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
            \\ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
            \\TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
            \\jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
            \\oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
            \\4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
            \\mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
            \\emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
        ;

        var der = try decodeBase64Cert(std.testing.allocator, cert_base64);
        defer std.testing.allocator.free(der);

        const cert = try parse(std.testing.allocator, der);
        if (!cert.validity.isValid(std.time.timestamp())) return error.Expired;

        var iter = cert.exts.?.iterator();
        while (iter.next()) |ext| {
            if (try ext.parse()) |e| {
                std.log.err("{}", .{e});
            }
        }
    }

    fn decodeBase64Cert(allocator: std.mem.Allocator, cert_base64: []const u8) ![]const u8 {
        const decoder = std.base64.standard.decoderWithIgnore(&[_]u8{'\n'});

        const size = try decoder.calcSizeUpperBound(cert_base64.len);
        var der = try std.ArrayList(u8).initCapacity(allocator, size);
        try der.appendNTimes(0, size);
        errdefer der.deinit();

        const n = try decoder.decode(der.items, cert_base64);
        try der.resize(n);
        return der.toOwnedSlice();
    }
};

test {
    _ = Certificate;
}

const DerDecoder = struct {
    data: []const u8,

    pub const Element = struct {
        tag: u8,
        data: []const u8,
    };

    fn parseInteger(bytes: []const u8) !Asn1.Integer {
        // Integer has a minumum length of 1.
        if (bytes.len == 0) return error.InvalidEncoding;
        if (bytes.len == 1) return bytes;

        // Not minimally encoded.
        // Integer might be prefixed with 0, so that it is not intepreted as negative.
        if (bytes[0] == 0 and bytes[1] & 0x80 == 0) return error.InvalidEncoding;
        // The first byte is unnecessary, removing it will result in the
        // same negative interpretation.
        if (bytes[0] == 0xff and bytes[1] & 0x80 == 0x80) return error.InvalidEncoding;

        return bytes;
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

const DerBuilder = struct {
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
