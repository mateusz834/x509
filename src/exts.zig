const std = @import("std");

const Asn1 = @import("./der.zig").Asn1;
const parseDirectoryString = @import("./der.zig").parseDirectoryString;
const isAscii = @import("./der.zig").isAscii;
const DerDecoder = @import("./der.zig").DerDecoder;
const DerBuilder = @import("./der.zig").DerBuilder;

pub const RawExts = struct {
    raw: []const u8,

    pub const Iterator = struct {
        decoder: DerDecoder,

        pub fn next(self: *Iterator) !?Ext {
            const sequence: u8 = 0x30;
            const oid = 0x06;
            const octetstring: u8 = 0x04;
            const boolean = 0x01;

            if (self.decoder.empty()) return null;

            var ext_decoder = DerDecoder{ .data = try self.decoder.getElementWithTag(sequence) };
            var ext = .{
                .oid = try ext_decoder.getElementWithTag(oid),
                .critical = try ext_decoder.getBooleanWithDefaultWithTag(false, boolean),
                .value = try ext_decoder.getElementWithTag(octetstring),
            };
            if (!ext_decoder.empty()) return error.InvalidEncoding;
            return ext;
        }
    };

    pub fn iterator(self: RawExts) Iterator {
        return .{ .decoder = .{ .data = self.raw } };
    }

    pub fn init(raw: []const u8) !RawExts {
        if (raw.len == 0) return error.InvalidEncoding;
        return .{ .raw = raw };
    }
};

pub const Ext = struct {
    oid: Asn1.RawObjectIdentifier,
    critical: bool,
    value: []const u8,
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

pub const RawSubjectKeyIdentifier = struct {
    const OID = Asn1.asRawObjectIdentifier(&[_]u64{ 2, 5, 29, 14 });

    key_identifier: []const u8,

    pub fn parse(der: []const u8) !RawSubjectKeyIdentifier {
        const octetstring: u8 = 0x04;
        var decoder = DerDecoder{ .data = der };
        const key_identifier = try decoder.getElementWithTag(octetstring);
        if (!decoder.empty()) return error.InvalidEncoding;
        return .{ .key_identifier = key_identifier };
    }
};

pub const RawAuthorityKeyIdentifier = struct {
    const OID = Asn1.asRawObjectIdentifier(&[_]u64{ 2, 5, 29, 35 });

    key_identifier: ?[]const u8,

    pub fn parse(der: []const u8) !RawAuthorityKeyIdentifier {
        const sequence: u8 = 0x30;

        var decoder = DerDecoder{ .data = der };
        const seq_raw = try decoder.getElementWithTag(sequence);
        if (!decoder.empty()) return error.InvalidEncoding;

        var seq_decoder = DerDecoder{ .data = seq_raw };

        var key_identifier: ?[]const u8 = null;

        if (try seq_decoder.getOptionalElementWithTag(0b10000000)) |bytes|
            key_identifier = bytes;

        // Thease fields are unused, must both present or both be absent.
        if (try seq_decoder.getOptionalElementWithTag(0b10000001)) |raw_gen_names| {
            try validateGeneralNames(raw_gen_names);
            if (try seq_decoder.getOptionalIntegerBytesWithTag(0b10000010) == null)
                return error.InvalidEncoding;
        }
        if (!seq_decoder.empty()) return error.InvalidEncoding;

        return .{ .key_identifier = key_identifier };
    }
};

fn validateGeneralNames(raw: []const u8) !void {
    var iter = try RawGeneralNamesIterator.init(raw);
    // TODO: try to parse the RawGeneralName to GeneralName
    while (try iter.next()) {}
}

const RawGeneralNamesIterator = struct {
    seq_of_decoder: DerDecoder,

    pub fn init(raw: []const u8) !RawGeneralNamesIterator {
        var seq_of_decoder = DerDecoder{ .data = raw };
        if (seq_of_decoder.empty()) return error.InvalidEncoding;
        return .{ .seq_of_decoder = seq_of_decoder };
    }

    pub fn next(self: *RawGeneralNamesIterator) !?RawGeneralName {
        if (self.empty()) return null;
        const el = try self.seq_of_decoder.getElement();
        return .{ .raw = try RawGeneralName.init(el) };
    }
};

pub const GeneralNameTag = enum {
    other,
    rfc822,
    dns,
    x400,
    directory,
    edi_party,
    uri,
    ip,
    registered_id,
};

// GeneralName contains a parsed general name.
// The contents of each specific name is not validated in any way
// to the rules specified by the x509 spec (i.e. the dns general name
// might not be a valid dns name/hostname or the ip might not be a valid
// IPv4/IPv6 binary address), only validations from ASN.1/DER are applied.
//
// It might be updated in future to containt more fields.
pub const GeneralName = union(GeneralNameTag) {
    rfc822: []const u8,
    dns: []const u8,
    url: []const u8,
    ip: []const u8,

    // They are all unused, but might be implemented in future.
    other: struct {},
    x400: struct {},
    directory: struct {},
    edi_party: struct {},
    registered_id: Asn1.RawObjectIdentifier,

    pub fn parse(der: []const u8) !GeneralName {
        const raw_general_name = try RawGeneralName.init(der);
        return raw_general_name.parse();
    }
};

pub const RawGeneralName = struct {
    raw: union(GeneralNameTag) {
        other: []const u8,
        rfc822: []const u8,
        dns: []const u8,
        x400: []const u8,
        directory: []const u8,
        edi_party: []const u8,
        uri: []const u8,
        ip: []const u8,
        registered_id: []const u8,
    },

    pub fn init(el: DerDecoder.Element) !RawGeneralName {
        const context_specific = 0b10000000;
        const constructed = 0b00100000;

        const raw = switch (el.tag) {
            0x00 | constructed | context_specific => .{ .other = el.data },
            0x01 | context_specific => .{ .rfc822 = el.data },
            0x02 | context_specific => .{ .dns = el.data },
            0x03 | constructed | context_specific => .{ .x400 = el.data },
            0x04 | constructed | context_specific => .{ .directory = el.data },
            0x05 | constructed | context_specific => .{ .edi_party = el.data },
            0x06 | context_specific => .{ .uri = el.data },
            0x07 | context_specific => .{ .ip = el.data },
            0x08 | context_specific => .{ .registered_id = el.data },
            else => return error.InvalidEncoding,
        };
        return .{ .raw = raw };
    }

    pub fn parse(self: RawGeneralName) !GeneralName {
        switch (self.raw) {
            .rfc822 => |raw| {
                if (!isAscii(raw)) return error.InvalidEncoding;
                return .{ .rfc822 = raw };
            },
            .dns => |raw| {
                if (!isAscii(raw)) return error.InvalidEncoding;
                return .{ .dns = raw };
            },
            .uri => |raw| {
                if (!isAscii(raw)) return error.InvalidEncoding;
                return .{ .uri = raw };
            },
            .ip => |raw| return .{ .ip = raw },
            .registered_id => |raw| {
                const oid = try DerDecoder.parseRawObjectIdentifier(raw);
                return .{ .registered_id = oid };
            },
            else => return error.InvalidEncoding,
        }
    }
};

pub const SubjectAlternativeName = struct {
    const OID = Asn1.asRawObjectIdentifier(&[_]u64{ 2, 5, 29, 17 });

    raw: []const u8,

    pub const Iterator = struct {
        iter: RawGeneralNamesIterator,

        pub fn next(self: *Iterator) !?GeneralName {
            if (try self.iter.next()) |rgn| return rgn.parse();
            return null;
        }
    };

    pub const RawIterator = struct {
        iter: RawGeneralNamesIterator,

        pub fn next(self: *RawIterator) !?RawGeneralName {
            return self.iter.next();
        }
    };

    pub fn iterator(self: SubjectAlternativeName) Iterator {
        return .{ .iter = RawGeneralNamesIterator.init(self.raw) catch unreachable };
    }

    pub fn rawIterator(self: SubjectAlternativeName) RawIterator {
        return .{ .iter = RawGeneralNamesIterator.init(self.raw) catch unreachable };
    }

    pub fn parse(der: []const u8) !SubjectAlternativeName {
        const sequence: u8 = 0x30;

        var decoder = DerDecoder{ .data = der };
        const seq_raw = try decoder.getElementWithTag(sequence);
        if (!decoder.empty()) return error.InvalidEncoding;

        // Make sure that the it contains at least one general name.
        // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
        _ = try RawGeneralNamesIterator.init(der);

        return .{ .raw = seq_raw };
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

pub const NameConstraints2 = struct {
    permitted: Constraints,
    excluded: Constraints,

    pub const Constraints = struct {
        rfc822: []const []const u8,
        dns: []const []const u8,
        url: []const []const u8,
        ip4: []const IPv4,
        ip6: []const IPv6,

        pub const IPv4 = struct {
            addr: [4]u8,
            mask: u8,
        };
        pub const IPv6 = struct {
            addr: [16]u8,
            mask: u8,
        };
    };
};
