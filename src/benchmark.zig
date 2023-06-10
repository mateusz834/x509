const std = @import("std");
const m = @import("./main.zig");

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

const stdout = std.io.getStdOut().writer();

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const cert_base64 =
        \\MIIJXjCCCEagAwIBAgIRAPYaTUsjP4iRBQAAAACHSSgwDQYJKoZIhvcNAQELBQAw
        \\QjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczET
        \\MBEGA1UEAxMKR1RTIENBIDFPMTAeFw0yMTAxMjYwODQ2MzRaFw0yMTA0MjAwODQ2
        \\MzNaMGYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
        \\Ew1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRUwEwYDVQQDDAwq
        \\Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC76xx0
        \\UdZ36/41rZNPfQ/yQ05vsBLUO0d+3uMOhvDlpst+XvIsG6L+vLDgf3RiQRFlei0h
        \\KqqLOtWLDc/y0+OmaaC+8ft1zljBYdvQlAYoZrT79Cc5pAIDq7G1OZ7cC4ahDno/
        \\n46FHjT/UTUAMYa8cKWBaMPneMIsKvn8nMdZzHkfO2nUd6OEecn90XweMvNmx8De
        \\6h5AlIgG3m66hkD/UCSdxn7yJHBQVdHgkfTqzv3sz2YyBQGNi288F1bn541f6khE
        \\fYti1MvXRtkky7yLCQNUG6PtvuSU4cKaNvRklHigf5i1nVdGEuH61gAElZIklSia
        \\OVK46UyU4DGtbdWNAgMBAAGjggYpMIIGJTAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0l
        \\BAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU8zCvllLd3jhB
        \\k//+Wdjo40Q+T3gwHwYDVR0jBBgwFoAUmNH4bhDrz5vsYJ8YkBug630J/SswaAYI
        \\KwYBBQUHAQEEXDBaMCsGCCsGAQUFBzABhh9odHRwOi8vb2NzcC5wa2kuZ29vZy9n
        \\dHMxbzFjb3JlMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2cvZ3NyMi9HVFMx
        \\TzEuY3J0MIIE1wYDVR0RBIIEzjCCBMqCDCouZ29vZ2xlLmNvbYINKi5hbmRyb2lk
        \\LmNvbYIWKi5hcHBlbmdpbmUuZ29vZ2xlLmNvbYIJKi5iZG4uZGV2ghIqLmNsb3Vk
        \\Lmdvb2dsZS5jb22CGCouY3Jvd2Rzb3VyY2UuZ29vZ2xlLmNvbYIYKi5kYXRhY29t
        \\cHV0ZS5nb29nbGUuY29tghMqLmZsYXNoLmFuZHJvaWQuY29tggYqLmcuY2+CDiou
        \\Z2NwLmd2dDIuY29tghEqLmdjcGNkbi5ndnQxLmNvbYIKKi5nZ3BodC5jboIOKi5n
        \\a2VjbmFwcHMuY26CFiouZ29vZ2xlLWFuYWx5dGljcy5jb22CCyouZ29vZ2xlLmNh
        \\ggsqLmdvb2dsZS5jbIIOKi5nb29nbGUuY28uaW6CDiouZ29vZ2xlLmNvLmpwgg4q
        \\Lmdvb2dsZS5jby51a4IPKi5nb29nbGUuY29tLmFygg8qLmdvb2dsZS5jb20uYXWC
        \\DyouZ29vZ2xlLmNvbS5icoIPKi5nb29nbGUuY29tLmNvgg8qLmdvb2dsZS5jb20u
        \\bXiCDyouZ29vZ2xlLmNvbS50coIPKi5nb29nbGUuY29tLnZuggsqLmdvb2dsZS5k
        \\ZYILKi5nb29nbGUuZXOCCyouZ29vZ2xlLmZyggsqLmdvb2dsZS5odYILKi5nb29n
        \\bGUuaXSCCyouZ29vZ2xlLm5sggsqLmdvb2dsZS5wbIILKi5nb29nbGUucHSCEiou
        \\Z29vZ2xlYWRhcGlzLmNvbYIPKi5nb29nbGVhcGlzLmNughEqLmdvb2dsZWNuYXBw
        \\cy5jboIUKi5nb29nbGVjb21tZXJjZS5jb22CESouZ29vZ2xldmlkZW8uY29tggwq
        \\LmdzdGF0aWMuY26CDSouZ3N0YXRpYy5jb22CEiouZ3N0YXRpY2NuYXBwcy5jboIK
        \\Ki5ndnQxLmNvbYIKKi5ndnQyLmNvbYIUKi5tZXRyaWMuZ3N0YXRpYy5jb22CDCou
        \\dXJjaGluLmNvbYIQKi51cmwuZ29vZ2xlLmNvbYITKi53ZWFyLmdrZWNuYXBwcy5j
        \\boIWKi55b3V0dWJlLW5vY29va2llLmNvbYINKi55b3V0dWJlLmNvbYIWKi55b3V0
        \\dWJlZWR1Y2F0aW9uLmNvbYIRKi55b3V0dWJla2lkcy5jb22CByoueXQuYmWCCyou
        \\eXRpbWcuY29tghphbmRyb2lkLmNsaWVudHMuZ29vZ2xlLmNvbYILYW5kcm9pZC5j
        \\b22CG2RldmVsb3Blci5hbmRyb2lkLmdvb2dsZS5jboIcZGV2ZWxvcGVycy5hbmRy
        \\b2lkLmdvb2dsZS5jboIEZy5jb4IIZ2dwaHQuY26CDGdrZWNuYXBwcy5jboIGZ29v
        \\LmdsghRnb29nbGUtYW5hbHl0aWNzLmNvbYIKZ29vZ2xlLmNvbYIPZ29vZ2xlY25h
        \\cHBzLmNughJnb29nbGVjb21tZXJjZS5jb22CGHNvdXJjZS5hbmRyb2lkLmdvb2ds
        \\ZS5jboIKdXJjaGluLmNvbYIKd3d3Lmdvby5nbIIIeW91dHUuYmWCC3lvdXR1YmUu
        \\Y29tghR5b3V0dWJlZWR1Y2F0aW9uLmNvbYIPeW91dHViZWtpZHMuY29tggV5dC5i
        \\ZTAhBgNVHSAEGjAYMAgGBmeBDAECAjAMBgorBgEEAdZ5AgUDMDMGA1UdHwQsMCow
        \\KKAmoCSGImh0dHA6Ly9jcmwucGtpLmdvb2cvR1RTMU8xY29yZS5jcmwwEwYKKwYB
        \\BAHWeQIEAwEB/wQCBQAwDQYJKoZIhvcNAQELBQADggEBAHh9/ozYUGRd+W5akWlM
        \\4WvX808TK2oUISnagbxCCFZ2trpg2oi03CJf4o4o3Je5Qzzz10s22oQY6gPHAR0B
        \\QHzrpqAveQw9D5vd8xjgtQ/SAujPzPKNQee5511rS7/EKW9I83ccd5XhhoEyx8A1
        \\/65RTS+2hKpJKTMkr0yHBPJV7kUW+n/KIef5YaSOA9VYK7hyH0niDpvm9EmoqvWS
        \\U5xAFAe/Xrrq3sxTuDJPQA8alk6h/ql5Klkw6dL53csiPka/MevDqdifWkzuT/6n
        \\YK/ePeJzPD17FA9V+N1rcuF3Wk29AZvCOSasdIkIuE82vGr3dfNrsrn9E9lWIbCr
        \\Qc4=
    ;

    var der = try decodeBase64Cert(allocator, cert_base64);
    defer allocator.free(der);

    try benchmarkCertificateParse(allocator, der, 300000);
    try benchmarkExtensionsIterateAndParse(allocator, der, 300000);
    try benchmarkExtensionsCache(allocator, der, 1000000);
}

fn benchmarkCertificateParse(allocator: std.mem.Allocator, der: []const u8, n: usize) !void {
    var timer = try std.time.Timer.start();
    const start = timer.lap();
    {
        for (0..n) |_| {
            const cert = try m.Certificate.parse(allocator, der);
            std.mem.doNotOptimizeAway(&cert);
        }
    }
    const end = timer.read();
    const elapsed = end - start;
    stdout.print("{} cert parse: total: {} ns, per iteration: {} ns, {} iterations per second\n", .{ n, elapsed, elapsed / n, std.time.ns_per_s / (elapsed / n) }) catch {};
}

fn benchmarkExtensionsIterateAndParse(allocator: std.mem.Allocator, der: []const u8, n: usize) !void {
    const cert = try m.Certificate.parse(allocator, der);

    var timer = try std.time.Timer.start();
    const start = timer.lap();
    {
        for (0..n) |_| {
            if (cert.exts) |exts| {
                var iter = exts.iterator();
                while (iter.next()) |raw_ext| {
                    if (try raw_ext.parse()) |ext| {
                        switch (ext) {
                            .subject_alt_name => |san| {
                                var san_iter = san.rawIterator();
                                while (san_iter.next()) |raw_general_name| {
                                    if (try raw_general_name.parse()) |general_name| {
                                        std.mem.doNotOptimizeAway(&general_name);
                                    }
                                }
                            },
                            else => {},
                        }
                        std.mem.doNotOptimizeAway(&ext);
                    }
                }
            }
        }
    }
    const end = timer.read();
    const elapsed = end - start;
    stdout.print("{} exts iter and parse: total: {} ns, per iteration: {} ns, {} iterations per second\n", .{ n, elapsed, elapsed / n, std.time.ns_per_s / (elapsed / n) }) catch {};
}

fn benchmarkExtensionsCache(allocator: std.mem.Allocator, der: []const u8, n: usize) !void {
    const cert = try m.Certificate.parse(allocator, der);

    var dns_names = std.ArrayList([]const u8).init(allocator);
    defer dns_names.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const arena_alloc = arena.allocator();

    if (cert.exts) |exts| {
        var iter = exts.iterator();
        while (iter.next()) |raw_ext| {
            if (try raw_ext.parse()) |ext| {
                switch (ext) {
                    .subject_alt_name => |san| {
                        var san_iter = san.rawIterator();
                        while (san_iter.next()) |raw_general_name| {
                            if (try raw_general_name.parse()) |general_name| {
                                switch (general_name) {
                                    .dns => |dns_name| {
                                        var dns = try arena_alloc.alloc(u8, dns_name.len);
                                        std.mem.copyForwards(u8, dns, dns_name);
                                        try dns_names.append(dns);
                                    },
                                    else => {},
                                }
                            }
                        }
                    },
                    else => {},
                }
            }
        }
    }

    var timer = try std.time.Timer.start();
    const start = timer.lap();
    {
        for (0..n) |_| {
            for (dns_names.items) |name| {
                std.mem.doNotOptimizeAway(&name);
            }
        }
    }
    const end = timer.read();
    const elapsed = end - start;
    stdout.print("{} exts cache: total: {} ns, per iteration: {} ns, {} iterations per second\n", .{ n, elapsed, elapsed / n, std.time.ns_per_s / (elapsed / n) }) catch {};
}
