const std = @import("std");
const builtin = @import("builtin");

const Asn1 = @import("./der.zig").Asn1;
const DerDecoder = @import("./der.zig").DerDecoder;
const DerBuilder = @import("./der.zig").DerBuilder;

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
            const constructed = 0b00100000;

            const oid = 0x06;
            const sequence: u8 = 0x30;
            _ = sequence;
            const set: u8 = 0x31;
            _ = set;

            switch (self.raw.tag) {
                // otherName
                constructed | context_specific | 0x0 => {
                    var d = DerDecoder{ .data = self.raw.data };
                    _ = try d.getRawObjectIdentifierWithTag(oid);
                    var d2 = DerDecoder{ .data = try d.getElementWithTag(constructed | context_specific | 0x00) };
                    _ = try d2.getElement();
                    if (!d.empty()) return error.InvalidEncoding;
                    if (!d2.empty()) return error.InvalidEncoding;
                    return null;
                },
                context_specific | 0x1 => {
                    if (!isAscii(self.raw.data)) return error.InvalidEncoding;
                    return .{ .rfc822 = self.raw.data };
                },
                context_specific | 0x2 => {
                    if (!isAscii(self.raw.data)) return error.InvalidEncoding;
                    return .{ .dns = self.raw.data };
                },
                // x400Address
                context_specific | 0x3 => {
                    //var d = DerDecoder{ .data = self.raw.data };
                    //var standard_attributes_decoder = DerDecoder{ .data = try d.getElementWithTag(sequence) };
                    //if (standard_attributes_decoder.getOptionalElementExplicit(0b01000001)) |country_name| {
                    //    switch (country_name.tag) {
                    //        18 => if (!isValidNumericString(country_name.data) or country_name.data != 3)
                    //            return error.InvalidEncoding,
                    //        19 => if (!isValidPrintableString(country_name.data, false) or country_name.data != 2)
                    //            return error.InvalidEncoding,
                    //        else => return error.InvalidEncoding,
                    //    }
                    //}
                    //if (standard_attributes_decoder.getOptionalElementExplicit(0b01000010)) |admininistration_domain_name| {
                    //    switch (admininistration_domain_name.tag) {
                    //        18 => if (!isValidNumericString(admininistration_domain_name.data) or admininistration_domain_name.data > 16)
                    //            return error.InvalidEncoding,
                    //        19 => if (!isValidPrintableString(admininistration_domain_name.data, false) or admininistration_domain_name.data > 16)
                    //            return error.InvalidEncoding,
                    //        else => return error.InvalidEncoding,
                    //    }
                    //}
                    //if (try d.getOptionalElementWithTag(sequence)) |raw| {
                    //    var domain_defined_attributes_decoder = DerDecoder{ .data = raw };
                    //    _ = domain_defined_attributes_decoder;
                    //}
                    //if (try d.getOptionalElementWithTag(set)) |raw| {
                    //    var extension_attributes_decoder = DerDecoder{ .data = raw };
                    //    _ = extension_attributes_decoder;
                    //}
                    //if (!d.empty()) return error.InvalidEncoding;
                    return null;
                },
                // ediPartyName
                context_specific | 0x5 => {
                    // This is bit weird, [0] means implicit, but DirectoryString is a choice
                    // so there is no way to detect the string type, so this must be
                    // with explicit tagging (probably ASN.1 defines this somewhere).
                    //
                    // (This is defined with: DEFINITIONS IMPLICIT TAGS)
                    //
                    // EDIPartyName ::= SEQUENCE {
                    //		nameAssigner            [0]     DirectoryString OPTIONAL,
                    //		partyName               [1]     DirectoryString }
                    //
                    // DirectoryString ::= CHOICE {
                    //		teletexString       TeletexString   (SIZE (1..MAX)),
                    // 		printableString     PrintableString (SIZE (1..MAX)),
                    // 		universalString     UniversalString (SIZE (1..MAX)),
                    // 		utf8String          UTF8String      (SIZE (1..MAX)),
                    // 		bmpString           BMPString       (SIZE (1..MAX)) }

                    var d = DerDecoder{ .data = self.raw.data };
                    if (try d.getOptionalElementExplicit(context_specific | 0x00)) |n| {
                        const el = try parseDirectoryString(n, null);
                        if (el.charCount() == 0) return error.InvalidEncoding;
                    }

                    const el = try parseDirectoryString(try d.getElementExplicit(context_specific | 0x01), null);
                    if (el.charCount() == 0) return error.InvalidEncoding;

                    if (!d.empty()) return error.InvalidEncoding;
                    return null;
                },
                context_specific | 0x6 => {
                    if (!isAscii(self.raw.data)) return error.InvalidEncoding;
                    return .{ .url = self.raw.data };
                },
                context_specific | 0x7 => return .{ .ip = self.raw.data },
                // registeredID
                context_specific | 0x8 => {
                    var d = DerDecoder{ .data = self.raw.data };
                    _ = try d.getRawObjectIdentifierWithTag(oid);
                    return null;
                },
                else => return null,
            }
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
                if (m.raw[0] & 0x80 != 0) return error.InvalidEncoding;
            }

            if (!seq_decoder.empty()) return error.InvalidEncoding;
            return .{
                .ca = ca,
                .max_path_length = max_path_length,
            };
        }
    };

    pub const NameConstraints = struct {
        const OID = Asn1.asRawObjectIdentifier(&[_]u64{ 2, 5, 29, 30 });

        permitted: ?RawGeneralSubtrees = null,
        excluded: ?RawGeneralSubtrees = null,

        pub const RawGeneralSubtrees = struct {
            raw: []const u8,

            pub const RawGeneralSubtree = struct {
                base: RawGeneralName,
            };

            pub const RawIterator = struct {
                seq_decoder: DerDecoder,

                pub fn next(self: *RawIterator) ?RawGeneralSubtree {
                    if (self.seq_decoder.empty()) return null;
                    const general_name = self.seq_decoder.getElement() catch unreachable;
                    return .{ .raw = general_name };
                }
            };

            pub fn rawIterator(self: SubjectAlternativeName) RawIterator {
                return .{ .seq_decoder = DerDecoder{ .data = self.raw } };
            }
        };

        pub fn parse(der: []const u8) !NameConstraints {
            const sequence: u8 = 0x30;

            var decoder = DerDecoder{ .data = der };
            const seq_raw = try decoder.getElementWithTag(sequence);
            if (!decoder.empty()) return error.InvalidEncoding;

            var seq_decoder = DerDecoder{ .data = seq_raw };

            if (try seq_decoder.getOptionalElementWithTag(0b01100000)) |raw_permitted_subtrees| {
                try validateGeneralSubtrees(DerDecoder{ .data = raw_permitted_subtrees });
            }
            if (try seq_decoder.getOptionalElementWithTag(0b01100001)) |raw_excluded_subtrees| {
                try validateGeneralSubtrees(DerDecoder{ .data = raw_excluded_subtrees });
            }

            if (!seq_decoder.empty()) return error.InvalidEncoding;

            return .{ .raw = seq_raw };
        }

        fn validateGeneralSubtrees(decoder: DerDecoder) !void {
            const sequence: u8 = 0x30;

            if (decoder.empty()) return error.InvalidEncoding;
            while (!decoder.empty()) {
                var general_subtree = DerDecoder{ .data = try decoder.getElementWithTag(sequence) };

                // TODO: validate GeneralName tag + same in subject alt name.
                _ = try general_subtree.getElement();

                if (try general_subtree.getOptionalIntegerBytesWithTag(0b01000000)) |int| {
                    if (int.as(u8)) |val| if (val == 0) return error.InvalidEncoding;
                }
                _ = try general_subtree.getOptionalIntegerBytesWithTag(0b01000001);
                if (!general_subtree.empty()) return error.InvalidEncoding;
            }
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

fn isValidNumericString(str: []const u8) bool {
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

pub const AttributeTypeAndValue = struct {
    oid: Asn1.RawObjectIdentifier,
    value: DerDecoder.Element,

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

    pub fn parse(self: Name.AttributeTypeAndValue) !?Entry {
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

pub const RawNameIterator = struct {
    rdn_sequence: DerDecoder,
    rdn_set: DerDecoder,
    prev_set_el: []const u8,

    pub fn init(raw: []const u8) !RawNameIterator {
        if (raw.len == 0) return error.InvalidEncoding;
        return .{
            .rdn_sequence = .{ .data = raw },
            .rdn_set = .{ .data = &[_]u8{} },
            .prev_set_el = &[_]u8{},
        };
    }

    pub fn next(self: *RawNameIterator) !?Name.AttributeTypeAndValue {
        const oid = 0x06;
        const set: u8 = 0x31;
        const sequence: u8 = 0x30;

        if (self.rdn_set.empty()) {
            if (self.rdn_sequence.empty()) return null;
            self.rdn_set = DerDecoder{
                .data = try self.rdn_sequence.getElementWithTag(set),
            };
            self.prev_set_el = &[_]u8{};
        }

        const raw = try self.rdn_set.getElementWithTag(sequence);

        if (self.prev_set_el.len != 0) {
            // ITU-T X.690: 11.6 Set-of components
            // The encodings of the component values of a set-of value shall appear in ascending order, the encodings being compared as
            // octet strings with the shorter components being padded at their trailing end with 0-octets.
            // NOTE – The padding octets are for comparison purposes only and do not appear in the encodings.
            if (!(self.prev_set_el.len < raw.len or std.mem.lessThan(u8, self.prev_set_el, raw)))
                return error.InvalidEncoding;
        }
        self.prev_set_el = raw;

        var atav_decoder = DerDecoder{ .data = raw };
        const atav = Name.AttributeTypeAndValue{
            .oid = try atav_decoder.getRawObjectIdentifierWithTag(oid),
            .value = try atav_decoder.getElement(),
        };
        if (!atav_decoder.empty()) return error.InvalidEncoding;
        return atav;
    }
};

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
        raw_name_iter: RawNameIterator,

        pub fn next(self: *RawIterator) ?Name.AttributeTypeAndValue {
            return self.raw_name_iter.next() catch unreachable;
        }
    };

    pub fn rawIterator(self: Name) RawIterator {
        return .{ .raw_name_iter = RawNameIterator.init(self.raw) catch unreachable };
    }

    pub const AttributeTypeAndValue = struct {
        oid: Asn1.RawObjectIdentifier,
        value: DerDecoder.Element,

        pub fn parse(self: Name.AttributeTypeAndValue) !?Entry {
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

    pub fn empty(name: Name) bool {
        var itr = name.rawIterator();
        if (itr.next() == null) return true;
        return false;
    }

    pub fn validAsSubject(name: Name, san_crit: bool) bool {
        if (!name.empty()) return true;
        if (san_crit) return true;
        return false;
    }

    pub fn parse(der: []const u8) !Name {
        var iter = try RawNameIterator.init(der);
        while (try iter.next()) |_| {}
        return .{ .raw = der };
    }

    test "parse" {
        const cn = "ROOT-CA";

        const der = try testBuildName(
            std.testing.allocator,
            &[_]Name.AttributeTypeAndValue{
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

    fn testBuildName(allocator: std.mem.Allocator, atavs: []const Name.AttributeTypeAndValue) ![]const u8 {
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

pub const Certificate = struct {
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

        pub fn hasDuplicates(self: Exts, allocator: std.mem.Allocator) !bool {
            var map = std.StringHashMap(void).init(allocator);
            defer map.deinit();

            var iter = self.iterator();
            while (iter.next()) |ext| {
                if (map.get(ext.oid)) |_| return true;
                try map.put(ext.oid, {});
            }

            return false;
        }

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

    // TODO: RFC 5280 6.1: (What is this??)
    // However, a CA may issue a certificate to itself to
    // support key rollover or changes in certificate policies.  These
    // self-issued certificates are not counted when evaluating path length
    // or name constraints.

    pub const ParseDiagnostics = struct {
        detail_error: union(enum) {
            malformed_certificate,
            malformed_tbs_certificate,
            malformed_signature_algorithm,
            malformed_signature,
            malformed_version,
            unsupported_cert_version: Asn1.Integer,
            malformed_serial_number,
            malformed_signature_algorithm_identifier,
            malformed_issuer,
            malformed_validity,
            malformed_subject,
            malformed_public_key_info,
            malformed_issuer_unique_id,
            malformed_subject_unique_id,
            malformed_exts,

            pub fn string(self: @This()) []const u8 {
                return switch (self) {
                    .malformed_certificate => "malformed certificate",
                    .malformed_tbs_certificate => "malformed tbs certificate",
                    .malformed_signature_algorithm => "malformed signature algorithm",
                    .malformed_signature => "malformed signature",
                    .malformed_tbs_certificate => "malformed tbs certificate",
                    .malformed_version => "malformed version",
                    .unsupported_cert_version => "unsupported certificate version",
                    .malformed_serial_number => "malformed serial number",
                    .malformed_signature_algorithm_identifier => "malformed signature algorithm identifier",
                    .malformed_issuer => "malformed issuer",
                    .malformed_validity => "malformed validity",
                    .malformed_subject => "malformed subject",
                    .malformed_public_key_info => "malformed public key info",
                    .malformed_issuer_unique_id => "malformed issuer unique id",
                    .malformed_subject_unique_id => "malformed subject unique id",
                    .malformed_exts => "malformed extensions",
                };
            }
        },
    };

    pub const ParseOptions = struct {};

    pub const Error = error{
        InvalidEncoding,
        UnsupportedVersion,
    } || std.mem.Allocator.Error;

    // parse parses a der encoded X509 certificate.
    // Fields in the returned Certificate share memory with the provided der slice.
    // allocator is used only for internal processing, no need to deinit a parsed certificate.
    pub fn parse(allocator: std.mem.Allocator, der: []const u8) Error!Certificate {
        _ = allocator;
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
            if (version_bytes.as(u8)) |version| {
                if (version == 0)
                    // As per DER, default values are not encoded.
                    return error.InvalidEncoding
                else if (version == 1)
                    break :blk .v2
                else if (version == 2)
                    break :blk .v3
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
        const serial_number = try tbs_certificate.getIntegerBytesWithTag(integer);

        const signature_algorithm_identifier = try parseAlgorithmIdentifier(try tbs_certificate.getElementWithTag(sequence));

        const issuer = try Name.parse(try tbs_certificate.getElementWithTag(sequence));
        // 4.1.2.4.  The issuer field MUST contain a non-empty distinguished name (DN).
        if (issuer.empty()) return error.InvalidEncoding;

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
                var exts_seq_decoder = DerDecoder{ .data = e };
                const exts_data = try exts_seq_decoder.getElementWithTag(sequence);
                if (!exts_seq_decoder.empty()) return error.InvalidEncoding;
                var exts_decoder = DerDecoder{ .data = exts_data };
                exts = .{ .raw = exts_data };

                if (exts_decoder.empty()) return error.InvalidEncoding;

                while (!exts_decoder.empty()) {
                    var extension_decoder = DerDecoder{ .data = try exts_decoder.getElementWithTag(sequence) };
                    _ = try extension_decoder.getRawObjectIdentifierWithTag(oid);
                    _ = try extension_decoder.getBooleanWithDefaultWithTag(false, boolean);
                    _ = try extension_decoder.getElementWithTag(octetstring);
                    if (!extension_decoder.empty()) return error.InvalidEncoding;
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

        //if (exts) |extensions| {
        //    if (try extensions.hasDuplicates(allocator)) return error.InvalidEncoding;
        //    var ext_iter = extensions.iterator();
        //    while (ext_iter.next()) |ext| {
        //        _ = try ext.parse();
        //    }
        //}

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
fn validateParent(issuer: *const Certificate, subject: *const Certificate) bool {
    // for all x in {1, ..., n-1}, the subject of certificate x is
    // the issuer of certificate x+1;
    if (!std.mem.eql(u8, issuer.subject.raw, subject.issuer.raw)) return false;

    // The signature on the certificate can be verified using
    // working_public_key_algorithm, the working_public_key, and
    // the working_public_key_parameters.
    const issuer_alg = issuer.subject_public_key_info.algorithm;
    const subject_alg = subject.signature_algorithm_identifier;
    if (!std.mem.eql(u8, issuer_alg.algorithm, subject_alg.algorithm)) return false;
    if (issuer_alg.paramters == null or subject_alg.paramters == null) {
        if (issuer_alg.paramters != null or subject_alg.paramters != null) return false;
        if (!std.mem.eql(u8, issuer_alg.paramters.?, subject_alg.paramters.?)) return false;
    }
}

pub const PathProcessingCertificate = struct {
    cert: *const Certificate,
    exts: Extensions,

    pub fn fromCert(cert: *const Certificate) !PathProcessingCertificate {
        return .{
            .cert = cert,
            .exts = if (cert.exts) |exts| try Extensions.fromExts(exts) else Extensions{},
        };
    }

    pub const Extensions = struct {
        basic_constraints: ?Ext.BasicConstraints = null,
        key_usage: ?Ext.KeyUsage = null,
        unhandled_critical: bool = false,

        pub fn fromExts(exts: Certificate.Exts) !Extensions {
            const basic_constraints: ?Ext.BasicConstraints = null;
            const key_usage: ?Ext.KeyUsage = null;
            const unhandled_critical = false;

            var ca_exts_iter = exts.iterator();
            while (ca_exts_iter.next()) |ca_raw_ext| {
                if (std.mem.eql(u8, ca_raw_ext.oid, Ext.BasicConstraints.OID)) {
                    basic_constraints = try Ext.BasicConstraints.parse(ca_raw_ext.value);
                } else if (std.mem.eql(u8, ca_raw_ext.oid, Ext.KeyUsage.OID)) {
                    key_usage = try Ext.KeyUsage.parse(ca_raw_ext.value);
                } else if (ca_raw_ext.critical) {
                    unhandled_critical = true;
                }
            }

            return .{
                .basic_constraints = basic_constraints,
                .key_usage = key_usage,
                .unhandled_critical = unhandled_critical,
            };
        }
    };
};

pub const ParsedNameConstraints = struct {
    permitted: Constraints,
    excluded: Constraints,

    pub const Constraints = struct {
        rfc822: []const []const u8,
        dns: []const []const u8,
        url: []const []const u8,
        ip4: []const IPv4,
        ip6: []const IPv6,

        pub const IPv4 = struct { addr: [4]u8, mask: u8 };
        pub const IPv6 = struct { addr: [16]u8, mask: u8 };
    };
};

pub const PathProcessingChainCertificate = struct {
    cert: Certificate,
    name_constraints: NameConstraints,

    pub const NameConstraints = union(enum) {
        raw: Ext.NameConstraints,
        parsed: *ParsedNameConstraints,
    };
};

pub const PathProcessingCert = union(enum) {
    raw: *PathProcessingCertificate,
    parsed: *PathProcessingCertificate,
};

pub const PathValidationState = struct {
    max_path_length: usize = std.math.maxInt(usize),

    pub fn isValidForChain(self: *PathValidationState, ctx: type, err: type, chain_next: fn (c: ctx) err!PathProcessingCert, cert: PathProcessingCertificate) err!bool {
        while (try chain_next()) |ca| {
            switch (ca) {
                inline else => |c| if (std.mem.eql(u8, c.cert.raw, cert.cert.raw)) return false,
            }
        }

        if (self.max_path_length == 0) return false;
        self.max_path_length -= 1;

        if (cert.exts.basic_constraints) |basic_constraints| {
            // cert is not a Certificate Authority.
            if (!basic_constraints.ca) return false;
            if (basic_constraints.max_path_length) |ca_max_path_length_asn1_integer| {
                // Map the ASN1.Integer to usize, when the max_path_length is bigger than usize,
                // then there is nothing to do, because the chain slice can't be bigger than usize.
                if (ca_max_path_length_asn1_integer.as(usize)) |ca_max_path_length| {
                    if (ca_max_path_length < self.max_path_length) {
                        self.max_path_length = ca_max_path_length;
                    }
                }
            } else {
                // RFC 5280 4.2.1.9:
                // If the basic constraints extension is not present in a
                // version 3 certificate, or the extension is present but the cA boolean
                // is not asserted, then the certified public key MUST NOT be used to
                // verify certificate signatures.
                return false;
            }
        }
    }
};

pub fn validateChain(chain: []*const Certificate, now_utc: i64) !bool {
    if (chain.len < 2) return false;

    // Trust anchor must be self-signed.
    if (!std.mem.eql(u8, chain[0].subject.raw, chain[0].issuer.raw)) return false;

    for (chain) |n| if (!n.validity.isValid(now_utc)) return false;

    // A certificate MUST NOT appear more than once in a prospective
    // certification path.
    //
    // The first certificate (trust anchor) can be excluded, because
    // it is self-signed, so it would be rejected in the loop above.
    // Certificate chains aren't that long, so the O(n^2) should be fine here.
    // For example golang (crypto/x509) bundling limits the total signature checks (up to 100)
    // https://github.com/golang/go/blob/7bc3281747030877e13d218ba12c6e95fcf4e7d4/src/crypto/x509/verify.go#L892C1-L896
    // TODO: might also limit the max chain length here and/or use StringHashMap with allocator.
    for (chain[1..], 0..) |n, ni| {
        for (chain[1..], 0..) |n2, n2i| {
            if (ni == n2i) continue;
            if (std.mem.eql(u8, n.raw, n2.raw)) return false;
        }
    }

    // RFC 5280 4.2.1.9: it gives the
    // maximum number of non-self-issued intermediate certificates that may
    // follow this certificate in a valid certification path.  (Note: The
    // last certificate in the certification path is not an intermediate
    // certificate, and is not included in this limit.
    // A pathLenConstraint of zero indicates that no non-
    // self-issued intermediate CA certificates may follow in a valid
    // certification path.
    var max_path_length: usize = std.math.maxInt(usize);

    for (chain[0 .. chain.len - 1], chain[1..]) |n1, n2| {
        // for all x in {1, ..., n-1}, the subject of certificate x is
        // the issuer of certificate x+1;
        if (!std.mem.eql(u8, n1.subject.raw, n2.issuer.raw)) return false;

        // The signature on the certificate can be verified using
        // working_public_key_algorithm, the working_public_key, and
        // the working_public_key_parameters.
        const n1_alg = n1.subject_public_key_info.algorithm;
        const n2_alg = n2.signature_algorithm_identifier;
        if (!std.mem.eql(u8, n1_alg.algorithm, n2_alg.algorithm)) return false;
        if (n1_alg.paramters == null or n2_alg.paramters == null) {
            if (n1_alg.paramters != null or n2_alg.paramters != null) return false;
            if (!std.mem.eql(u8, n1_alg.paramters.?, n2_alg.paramters.?)) return false;
        }
        // TODO: verify signature of n2 using n1 key.

        const ca_cert = n1;

        if (max_path_length == 0) return false;
        max_path_length -= 1;

        if (ca_cert.exts) |ca_exts| {
            var ca_exts_iter = ca_exts.iterator();
            while (ca_exts_iter.next()) |ca_raw_ext| {
                if (std.mem.eql(u8, ca_raw_ext.oid, Ext.BasicConstraints.OID)) {
                    const basic_constraints = try Ext.BasicConstraints.parse(ca_raw_ext.value);
                    // ca_cert is not a Certificate Authority.
                    if (!basic_constraints.ca) return false;
                    if (basic_constraints.max_path_length) |ca_max_path_length_asn1_integer| {
                        // Map the ASN1.Integer to usize, when the max_path_length is bigger than usize,
                        // then there is nothing to do, because the chain slice can't be bigger than usize.
                        if (ca_max_path_length_asn1_integer.as(usize)) |ca_max_path_length| {
                            if (ca_max_path_length < max_path_length) {
                                max_path_length = ca_max_path_length;
                            }
                        }
                    } else {
                        // RFC 5280 4.2.1.9:
                        // If the basic constraints extension is not present in a
                        // version 3 certificate, or the extension is present but the cA boolean
                        // is not asserted, then the certified public key MUST NOT be used to
                        // verify certificate signatures.
                        return false;
                    }
                } else if (std.mem.eql(u8, ca_raw_ext.oid, Ext.KeyUsage.OID)) {
                    const key_usage = try Ext.KeyUsage.parse(ca_raw_ext.value);
                    // If a key usage extension is present, verify that the keyCertSign bit is set.
                    if (!key_usage.key_cert_sig) return false;
                } else if (ca_raw_ext.critical) {
                    // Unhandled critical extension.
                    return false;
                }
            }
        }
    }

    return true;
}

test "n" {
    _ = validateChain(&[_]*const Certificate{}, 11) catch false;
}

test {
    _ = Certificate;
}
