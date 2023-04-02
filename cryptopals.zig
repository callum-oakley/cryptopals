const std = @import("std");

var arena: *std.heap.ArenaAllocator = undefined;
var allocator: std.mem.Allocator = undefined;

fn init() !void {
    arena = try std.heap.page_allocator.create(std.heap.ArenaAllocator);
    errdefer std.heap.page_allocator.destroy(arena);

    arena.* = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    errdefer arena.deinit();

    allocator = arena.allocator();
}

fn deinit() void {
    arena.deinit();
    arena.child_allocator.destroy(arena);
}

fn countWhitespace(s: []const u8) usize {
    var count: usize = 0;
    for (s) |c| {
        if (std.ascii.isWhitespace(c)) {
            count += 1;
        }
    }
    return count;
}

fn stripWhitespace(s: []const u8) ![]const u8 {
    const whitespace_count = countWhitespace(s);
    if (whitespace_count == 0) {
        return s;
    }
    var buf = try allocator.alloc(u8, s.len - whitespace_count);
    var i: usize = 0;
    for (s) |c| {
        if (!std.ascii.isWhitespace(c)) {
            buf[i] = c;
            i += 1;
        }
    }
    return buf;
}

fn hexToBytes(hex: []const u8) ![]u8 {
    var buf = try allocator.alloc(u8, hex.len / 2);
    return std.fmt.hexToBytes(buf, hex);
}

fn bytesToHex(bytes: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{}",
        .{std.fmt.fmtSliceHexLower(bytes)},
    );
}

fn base64ToBytes(base64: []const u8) ![]u8 {
    const len = try std.base64.standard.Decoder.calcSizeForSlice(base64);
    var buf = try allocator.alloc(u8, len);
    try std.base64.standard.Decoder.decode(buf, base64);
    return buf;
}

fn bytesToBase64(bytes: []const u8) ![]u8 {
    const len = std.base64.standard.Encoder.calcSize(bytes.len);
    var buf = try allocator.alloc(u8, len);
    _ = std.base64.standard.Encoder.encode(buf, bytes);
    return buf;
}

test "Set 1 / Challenge 1: Convert hex to base64" {
    try init();
    defer deinit();

    try std.testing.expectEqualSlices(
        u8,
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        try bytesToBase64(
            try hexToBytes(
                try stripWhitespace(
                    \\ 49276d206b696c6c696e6720796f757220627261696e206c
                    \\ 696b65206120706f69736f6e6f7573206d757368726f6f6d
                ),
            ),
        ),
    );

    try std.testing.expectEqualSlices(
        u8,
        try stripWhitespace(
            \\ 49276d206b696c6c696e6720796f757220627261696e206c
            \\ 696b65206120706f69736f6e6f7573206d757368726f6f6d
        ),
        try bytesToHex(
            try base64ToBytes(
                "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
            ),
        ),
    );
}

fn xor(a: []const u8, b: []const u8) ![]u8 {
    var buf = try allocator.alloc(u8, a.len);
    for (0..buf.len) |i| {
        buf[i] = a[i] ^ b[i % b.len];
    }
    return buf;
}

test "Set 1 / Challenge 2: Fixed XOR" {
    try init();
    defer deinit();

    try std.testing.expectEqualSlices(
        u8,
        "746865206b696420646f6e277420706c6179",
        try bytesToHex(try xor(
            try hexToBytes("1c0111001f010100061a024b53535009181c"),
            try hexToBytes("686974207468652062756c6c277320657965"),
        )),
    );
}

// According to https://en.wikipedia.org/wiki/Letter_frequency
const charsByFreq = "ETAOINSHRDLCUMWFGYPBVKJXQZ";

/// Scores a text by character frequency. Higher is better.
fn charFreqScore(text: []const u8) usize {
    var score: usize = 0;
    for (text) |c| {
        if (!(std.ascii.isPrint(c) or c == '\n')) {
            return 0;
        }
        for (charsByFreq, 0..) |d, i| {
            if (std.ascii.toUpper(c) == d) {
                score += charsByFreq.len - i;
                break;
            }
        }
    }
    return score;
}

const BreakSingleByteXorResult = struct {
    key: u8,
    plaintext: []u8,
    score: usize,
};

fn breakSingleByteXor(ciphertext: []const u8) !BreakSingleByteXorResult {
    var best_res: ?BreakSingleByteXorResult = null;
    var key: u8 = 0;
    while (true) : (key += 1) {
        const plaintext = try xor(ciphertext, &[_]u8{key});
        const score = charFreqScore(plaintext);
        if (best_res == null or score > best_res.?.score) {
            best_res = .{ .key = key, .plaintext = plaintext, .score = score };
        }
        if (key == 0xff) break;
    }
    return best_res.?;
}

test "Set 1 / Challenge 3: Single-byte XOR cipher" {
    try init();
    defer deinit();

    const ciphertext = try hexToBytes(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
    );
    try std.testing.expectEqualSlices(
        u8,
        "Cooking MC's like a pound of bacon",
        (try breakSingleByteXor(ciphertext)).plaintext,
    );
}

test "Set 1 / Challenge 4: Detect single-character XOR" {
    try init();
    defer deinit();

    const f = try std.fs.cwd().openFile("data/4.txt", .{});
    defer f.close();

    var buf: [64]u8 = undefined;

    var best_res: ?BreakSingleByteXorResult = null;
    while (try f.reader().readUntilDelimiterOrEof(&buf, '\n')) |line| {
        const ciphertext = try hexToBytes(line);
        const res = try breakSingleByteXor(ciphertext);
        if (best_res == null or res.score > best_res.?.score) best_res = res;
    }

    try std.testing.expectEqualSlices(
        u8,
        "Now that the party is jumping\n",
        best_res.?.plaintext,
    );
}

test "Set 1 / Challenge 5: Implement repeating-key XOR" {
    try init();
    defer deinit();

    const plaintext =
        \\Burning 'em, if you ain't quick and nimble
        \\I go crazy when I hear a cymbal
    ;

    try std.testing.expectEqualSlices(
        u8,
        try stripWhitespace(
            \\ 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262263
            \\ 24272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b2028
            \\ 3165286326302e27282f
        ),
        try bytesToHex(try xor(plaintext, "ICE")),
    );
}

fn hammingDistance(as: []const u8, bs: []const u8) usize {
    var dist: usize = 0;
    for (as, bs) |a, b| {
        const c = a ^ b;
        var i: u3 = 0;
        while (true) : (i += 1) {
            dist += (c >> i) & 1;
            if (i == 7) break;
        }
    }
    return dist;
}

const BreakRepeatingKeyXorResult = struct {
    key: []const u8,
    plaintext: []const u8,
};

fn breakRepeatingKeyXor(ciphertext: []const u8) !BreakRepeatingKeyXorResult {
    var best_keysize: ?usize = null;
    var best_average_cost: ?f64 = null;
    for (2..40) |keysize| {
        var blocks = std.mem.window(u8, ciphertext, keysize, keysize);
        const first = blocks.first();
        var total_cost: f64 = 0;
        var cost_count: f64 = 0;
        while (blocks.next()) |block| {
            if (block.len < keysize) break;
            total_cost +=
                @intToFloat(f64, hammingDistance(first, block)) /
                @intToFloat(f64, keysize);
            cost_count += 1;
        }
        const average_cost = total_cost / cost_count;
        if (best_average_cost == null or average_cost < best_average_cost.?) {
            best_keysize = keysize;
            best_average_cost = average_cost;
        }
    }

    const block_size = best_keysize.?;
    const block_count = try std.math.divCeil(usize, ciphertext.len, block_size);

    var transposed = try allocator.alloc(u8, block_count * block_size);
    {
        var blocks = std.mem.window(u8, ciphertext, block_size, block_size);
        var i: usize = 0;
        while (blocks.next()) |block| : (i += 1) {
            for (block, 0..) |byte, j| {
                transposed[j * block_count + i] = byte;
            }
        }
    }

    var key = try allocator.alloc(u8, block_size);
    var plaintext = try allocator.alloc(u8, ciphertext.len);
    {
        var blocks = std.mem.window(u8, transposed, block_count, block_count);
        var i: usize = 0;
        while (blocks.next()) |block| : (i += 1) {
            // Since our ciphertext didn't necessarily divide cleanly in to
            // blocks of length block_size, our transposed blocks can contain a
            // single nonsense byte at the end which needs special treatment.
            const has_nonsense_byte = transposed.len - block_size + i >= plaintext.len;
            const block_res = try breakSingleByteXor(
                if (has_nonsense_byte) block[0 .. block_count - 1] else block,
            );
            key[i] = block_res.key;
            for (block_res.plaintext, 0..) |byte, j| {
                plaintext[j * block_size + i] = byte;
            }
        }
    }

    return .{ .key = key, .plaintext = plaintext };
}

test "Set 1 / Challenge 6: Break repeating-key XOR" {
    try init();
    defer deinit();

    try std.testing.expectEqual(
        @as(usize, 37),
        hammingDistance("this is a test", "wokka wokka!!!"),
    );

    const f = try std.fs.cwd().openFile("data/6.txt", .{});
    defer f.close();

    const res = try breakRepeatingKeyXor(
        try base64ToBytes(
            try stripWhitespace(
                try f.readToEndAlloc(allocator, 5000),
            ),
        ),
    );

    try std.testing.expectEqualSlices(u8, "Terminator X: Bring the noise", res.key);
    try std.testing.expectEqualSlices(u8,
        \\I'm back and I'm ringin' the bell 
        \\A rockin' on the mike while the fly girls yell 
        \\In ecstasy in the back of me 
        \\Well that's my DJ Deshay cuttin' all them Z's 
        \\Hittin' hard and the girlies goin' crazy 
        \\Vanilla's on the mike, man I'm not lazy. 
        \\
        \\I'm lettin' my drug kick in 
        \\It controls my mouth and I begin 
        \\To just let it flow, let my concepts go 
        \\My posse's to the side yellin', Go Vanilla Go! 
        \\
        \\Smooth 'cause that's the way I will be 
        \\And if you don't give a damn, then 
        \\Why you starin' at me 
        \\So get off 'cause I control the stage 
        \\There's no dissin' allowed 
        \\I'm in my own phase 
        \\The girlies sa y they love me and that is ok 
        \\And I can dance better than any kid n' play 
        \\
        \\Stage 2 -- Yea the one ya' wanna listen to 
        \\It's off my head so let the beat play through 
        \\So I can funk it up and make it sound good 
        \\1-2-3 Yo -- Knock on some wood 
        \\For good luck, I like my rhymes atrocious 
        \\Supercalafragilisticexpialidocious 
        \\I'm an effect and that you can bet 
        \\I can take a fly girl and make her wet. 
        \\
        \\I'm like Samson -- Samson to Delilah 
        \\There's no denyin', You can try to hang 
        \\But you'll keep tryin' to get my style 
        \\Over and over, practice makes perfect 
        \\But not if you're a loafer. 
        \\
        \\You'll get nowhere, no place, no time, no girls 
        \\Soon -- Oh my God, homebody, you probably eat 
        \\Spaghetti with a spoon! Come on and say it! 
        \\
        \\VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino 
        \\Intoxicating so you stagger like a wino 
        \\So punks stop trying and girl stop cryin' 
        \\Vanilla Ice is sellin' and you people are buyin' 
        \\'Cause why the freaks are jockin' like Crazy Glue 
        \\Movin' and groovin' trying to sing along 
        \\All through the ghetto groovin' this here song 
        \\Now you're amazed by the VIP posse. 
        \\
        \\Steppin' so hard like a German Nazi 
        \\Startled by the bases hittin' ground 
        \\There's no trippin' on mine, I'm just gettin' down 
        \\Sparkamatic, I'm hangin' tight like a fanatic 
        \\You trapped me once and I thought that 
        \\You might have it 
        \\So step down and lend me your ear 
        \\'89 in my time! You, '90 is my year. 
        \\
        \\You're weakenin' fast, YO! and I can tell it 
        \\Your body's gettin' hot, so, so I can smell it 
        \\So don't be mad and don't be sad 
        \\'Cause the lyrics belong to ICE, You can call me Dad 
        \\You're pitchin' a fit, so step back and endure 
        \\Let the witch doctor, Ice, do the dance to cure 
        \\So come up close and don't be square 
        \\You wanna battle me -- Anytime, anywhere 
        \\
        \\You thought that I was weak, Boy, you're dead wrong 
        \\So come on, everybody and sing this song 
        \\
        \\Say -- Play that funky music Say, go white boy, go white boy go 
        \\play that funky music Go white boy, go white boy, go 
        \\Lay down and boogie and play that funky music till you die. 
        \\
        \\Play that funky music Come on, Come on, let me hear 
        \\Play that funky music white boy you say it, say it 
        \\Play that funky music A little louder now 
        \\Play that funky music, white boy Come on, Come on, Come on 
        \\Play that funky music 
        \\
    , res.plaintext);
}
