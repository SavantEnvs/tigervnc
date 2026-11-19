#!/usr/bin/env python3
"""Writes the committed seed corpora under mayhem/<target>/testsuite/.

Each seed is a small, well-formed RFB exchange (or config/host string) that
reaches one feature, so the fuzzer starts past the framing. Run from the repo
root: python3 mayhem/harnesses/gen_seeds.py
"""
import os
import struct
import zlib

def u8(v): return struct.pack(">B", v)
def u16(v): return struct.pack(">H", v)
def u32(v): return struct.pack(">I", v & 0xffffffff)
def s32(v): return struct.pack(">i", v)

# 32bpp, depth 24, little endian, true colour, rgb shifts 16/8/0
PF32 = u8(32) + u8(24) + u8(0) + u8(1) + u16(255) * 3 + u8(16) + u8(8) + u8(0) + b"\0" * 3
PF16 = u8(16) + u8(16) + u8(0) + u8(1) + u16(31) + u16(63) + u16(31) + u8(11) + u8(5) + u8(0) + b"\0" * 3
PF8CM = u8(8) + u8(8) + u8(0) + u8(0) + u16(0) * 3 + u8(0) * 3 + b"\0" * 3

W, H = 32, 16

def server_init(pf=PF32, w=W, h=H, name=b"fuzz"):
    return u16(w) + u16(h) + pf + u32(len(name)) + name

def rect(x, y, w, h, enc):
    return u16(x) + u16(y) + u16(w) + u16(h) + s32(enc)

def fbu(*rects):
    return u8(0) + b"\0" + u16(len(rects)) + b"".join(rects)

def px(r, g, b):  # PF32 pixel, little endian
    return bytes([b, g, r, 0])

def raw(w, h):
    return b"".join(px(x * 8, y * 16, 128) for y in range(h) for x in range(w))

def cpixel(r, g, b):  # Tight/ZRLE compact pixel for depth 24
    return bytes([b, g, r])

def client_msg_seeds():
    s = {}
    s["raw"] = server_init() + fbu(rect(0, 0, 8, 4, 0) + raw(8, 4))
    s["copyrect"] = server_init() + fbu(rect(0, 0, 8, 4, 0) + raw(8, 4),
                                        rect(8, 4, 8, 4, 1) + u16(0) + u16(0))
    s["rre"] = server_init() + fbu(rect(0, 0, 16, 8, 2) + u32(2) + px(1, 2, 3) +
                                   px(200, 0, 0) + u16(1) + u16(1) + u16(4) + u16(2) +
                                   px(0, 200, 0) + u16(6) + u16(3) + u16(3) + u16(3))
    # Hextile: one 16x16 tile, background + foreground + 2 subrects
    tile = u8(0x02 | 0x04 | 0x08) + px(10, 10, 10) + px(250, 250, 0) + u8(2) + u8(0x11) + u8(0x22) + u8(0x55) + u8(0x33)
    raw_tile = u8(0x01) + raw(16, 16)
    s["hextile"] = server_init() + fbu(rect(0, 0, 16, 16, 5) + tile, rect(16, 0, 16, 16, 5) + raw_tile)
    # ZRLE: one 64x64 tile is clipped to 8x4; solid tile (subencoding 1)
    z = zlib.compressobj()
    zdata = z.compress(u8(1) + cpixel(1, 2, 3)) + z.flush(zlib.Z_SYNC_FLUSH)
    s["zrle"] = server_init() + fbu(rect(0, 0, 8, 4, 16) + u32(len(zdata)) + zdata)
    # Tight: fill, then basic copy filter with an uncompressed (<12 bytes) payload
    tight_fill = rect(0, 0, 8, 8, 7) + u8(0x80) + cpixel(9, 8, 7)
    tight_copy = rect(8, 0, 2, 1, 7) + u8(0x00) + cpixel(1, 1, 1) + cpixel(2, 2, 2)
    z = zlib.compressobj()
    pal = z.compress(b"\x00\x01" * 8) + z.flush(zlib.Z_SYNC_FLUSH)
    tight_pal = (rect(0, 8, 16, 1, 7) + u8(0x40) + u8(1) + u8(1) + cpixel(0, 0, 0) + cpixel(255, 255, 255)
                 + u8(len(b"\x00\x01" * 8) // 8 * 0 + 2) + b"\x55\xaa")
    s["tight"] = server_init() + fbu(tight_fill, tight_copy, tight_pal)
    # Cursor pseudo-encodings
    cw, ch = 4, 4
    s["cursor"] = server_init() + fbu(rect(1, 1, cw, ch, -239) + raw(cw, ch) + b"\xf0" * ch)
    s["xcursor"] = server_init() + fbu(rect(0, 0, 8, 2, -240) + b"\xff\x00\x00" + b"\x00\xff\x00" + b"\xaa" * 2 + b"\xff" * 2)
    s["cursor_alpha"] = server_init() + fbu(rect(0, 0, 2, 2, -314) + s32(0) + b"\x10\x20\x30\x80" * 4)
    s["cursor_pf16"] = server_init(pf=PF16) + fbu(rect(0, 0, 2, 2, -239) + b"\x1f\x00" * 4 + b"\xc0\xc0")
    s["desktop_size"] = server_init() + fbu(rect(0, 0, 40, 20, -223))
    s["ext_desktop_size"] = server_init() + fbu(rect(0, 0, 40, 20, -308) + u8(1) + b"\0" * 3 +
                                                u32(1) + u16(0) + u16(0) + u16(40) + u16(20) + u32(0))
    s["desktop_name_led"] = server_init() + fbu(rect(0, 0, 0, 0, -307) + u32(5) + b"hello",
                                                rect(0, 0, 0, 0, -261) + u8(3),
                                                rect(0, 0, 0, 0, -224))
    s["colourmap"] = server_init(pf=PF8CM) + u8(1) + b"\0" + u16(0) + u16(2) + u16(65535) * 3 + u16(0) * 3 + \
        fbu(rect(0, 0, 2, 1, 0) + b"\x00\x01")
    s["bell_cuttext"] = server_init() + u8(2) + u8(3) + b"\0" * 3 + u32(11) + b"hello\nworld"
    # Extended clipboard: caps (flags=caps|text, one max size)
    caps = u32(0x01000000 | 0x01) + u32(1024)
    s["ext_clipboard_caps"] = server_init() + u8(3) + b"\0" * 3 + s32(-len(caps)) + caps
    z = zlib.compressobj()
    prov = z.compress(u32(6) + b"hello\0") + z.flush()
    provide = u32(0x10000000 | 0x01) + prov
    s["ext_clipboard_provide"] = server_init() + u8(3) + b"\0" * 3 + s32(-len(caps)) + caps + \
        u8(3) + b"\0" * 3 + s32(-len(provide)) + provide
    s["fence"] = server_init() + u8(248) + b"\0" * 3 + u32(0x80000000 | 0x4) + u8(4) + b"abcd" + \
        u8(248) + b"\0" * 3 + u32(0x80000000) + u8(0)
    s["end_cu"] = server_init() + u8(150)
    s["qemu_audio"] = server_init() + u8(255) + u8(1) + u16(2) + u8(255) + u8(1) + u16(0)
    return s

def client_handshake_seeds():
    si = server_init()
    v8 = b"RFB 003.008\n"
    s = {}
    s["none_38"] = v8 + u8(1) + u8(1) + u32(0) + si + fbu(rect(0, 0, 2, 2, 0) + raw(2, 2))
    s["none_33"] = b"RFB 003.003\n" + u32(1) + si
    s["vncauth"] = v8 + u8(2) + u8(1) + u8(2) + bytes(range(16)) + u32(0) + si
    s["auth_failed"] = v8 + u8(1) + u8(2) + bytes(range(16)) + u32(1) + u32(6) + b"denied"
    s["no_types"] = v8 + u8(0) + u32(9) + b"go away\n!"
    # VeNCrypt 0.2, subtype list [Plain], accept
    s["vencrypt_plain"] = v8 + u8(1) + u8(19) + u8(0) + u8(2) + u8(0) + u8(1) + u32(256) + u8(1) + u32(0) + si
    # DH: generator, key length, modulus, server public key
    p = (0xffffffffffffffc5).to_bytes(8, "big")
    s["dh"] = v8 + u8(1) + u8(30) + u16(5) + u16(8) + p + (123456789).to_bytes(8, "big") + u32(0) + si
    s["mslogon2"] = v8 + u8(1) + u8(113) + (5).to_bytes(8, "big") + p + (987654321).to_bytes(8, "big") + u32(0) + si
    # RA2: server public key length (bits), modulus, exponent
    n = bytes([0xc5] + [0x5a] * 126 + [0x01])
    e = bytes(127) + b"\x03"
    s["ra2"] = v8 + u8(1) + u8(5) + u32(1024) + n + e
    s["ra2_256"] = v8 + u8(1) + u8(129) + u32(1024) + n + e
    return s

def cmsg_setpf(pf): return u8(0) + b"\0" * 3 + pf
def cmsg_setenc(*encs): return u8(2) + b"\0" + u16(len(encs)) + b"".join(s32(e) for e in encs)
def cmsg_fbur(inc, x, y, w, h): return u8(3) + u8(inc) + u16(x) + u16(y) + u16(w) + u16(h)

def server_msg_seeds():
    hs = b"RFB 003.008\n" + u8(1) + u8(1)  # sec type None, shared
    s = {}
    for name, enc in (("raw", 0), ("rre", 2), ("hextile", 5), ("tight", 7), ("zrle", 16), ("jpeg", 21)):
        s["update_" + name] = hs + cmsg_setenc(enc, -239, -223, -308, -312, -313, -32 + 5, -256 + 6) + cmsg_fbur(0, 0, 0, 64, 48)
    s["setpf16_update"] = hs + cmsg_setpf(PF16) + cmsg_setenc(16, 5) + cmsg_fbur(0, 0, 0, 64, 48) + cmsg_fbur(1, 0, 0, 64, 48)
    s["setpf8_update"] = hs + cmsg_setpf(PF8CM) + cmsg_setenc(0) + cmsg_fbur(0, 0, 0, 16, 16)
    s["key_pointer"] = hs + u8(4) + u8(1) + b"\0\0" + u32(0x61) + u8(4) + u8(0) + b"\0\0" + u32(0x61) + \
        u8(5) + u8(1) + u16(10) + u16(10) + u8(5) + u8(0) + u16(11) + u16(12)
    s["cuttext"] = hs + u8(6) + b"\0" * 3 + u32(11) + b"hello\nworld"
    caps = u32(0x01000000 | 0x01) + u32(1024)
    z = zlib.compressobj()
    provide = u32(0x10000000 | 0x01) + z.compress(u32(6) + b"hello\0") + z.flush()
    s["ext_clipboard"] = hs + cmsg_setenc(int.from_bytes(struct.pack(">I", 0xC0A1E5CE), "big", signed=True)) + \
        u8(6) + b"\0" * 3 + s32(-len(caps)) + caps + u8(6) + b"\0" * 3 + s32(-len(provide)) + provide + \
        u8(6) + b"\0" * 3 + s32(-4) + u32(0x08000000 | 0x01)
    s["fence"] = hs + cmsg_setenc(-312) + u8(248) + b"\0" * 3 + u32(0x80000000 | 0x4 | 0x1) + u8(3) + b"xyz" + \
        u8(248) + b"\0" * 3 + u32(0x80000000) + u8(0) + cmsg_fbur(0, 0, 0, 8, 8)
    s["continuous"] = hs + cmsg_setenc(-313, -312, 0) + u8(150) + u8(1) + u16(0) + u16(0) + u16(64) + u16(48) + \
        cmsg_fbur(1, 0, 0, 64, 48) + u8(150) + u8(0) + u16(0) + u16(0) + u16(64) + u16(48)
    s["setdesktopsize"] = hs + cmsg_setenc(-308) + u8(251) + b"\0" + u16(80) + u16(60) + u8(1) + b"\0" + \
        u32(1) + u16(0) + u16(0) + u16(80) + u16(60) + u32(0)
    s["qemu_key"] = hs + cmsg_setenc(-258) + u8(255) + u8(0) + u16(1) + u32(0x61) + u32(30) + \
        u8(255) + u8(0) + u16(0) + u32(0x61) + u32(30)
    s["v33"] = b"RFB 003.003\n" + u8(0) + cmsg_fbur(0, 0, 0, 64, 48)
    return s

def server_auth_seeds():
    v8 = b"RFB 003.008\n"
    s = {}
    s["vncauth"] = v8 + u8(2) + bytes(range(16)) + u8(1) + cmsg_fbur(0, 0, 0, 8, 8)
    s["vncauth_33"] = b"RFB 003.003\n" + bytes(range(16))
    s["vencrypt_plain"] = v8 + u8(19) + u8(0) + u8(2) + u32(256) + u32(4) + u32(4) + b"userpass"
    n = bytes([0xc5] + [0x5a] * 126 + [0x01])
    e = bytes(127) + b"\x03"
    for name, t in (("ra2", 5), ("ra2ne", 6), ("ra2_256", 129), ("ra2ne_256", 130)):
        s[name] = v8 + u8(t) + u32(1024) + n + e + u16(128) + bytes(128)
    return s

def hostport_seeds():
    return {k: v.encode() for k, v in {
        "host": "localhost", "display": "example.com:1", "port": "10.0.0.1::5901",
        "v6": "[::1]:2", "v6port": "[fe80::1%eth0]::5999", "filter": "+192.168.0.0/16,-10.0.0.1,?",
        "filter6": "+::1/128,-fe80::/10,+0.0.0.0/0", "bare_v6": "::1"}.items()}

def viewer_config_seeds():
    hdr = b"TigerVNC Configuration file Version 1.0\n"
    return {
        "basic": hdr + b"ServerName=example.com\\c1\nShared=1\nQualityLevel=7\nPreferredEncoding=ZRLE\n",
        "monitors": hdr + b"FullScreen=1\nFullScreenMode=Selected\nFullScreenSelectedMonitors=1,3\n",
        "escapes": hdr + b"# comment\r\nServerName=a\\\\b\\n\\r\\cx\nDesktopSize=1024x768\nvia=gw::22\n",
        "deprecated": hdr + b"DotWhenNoCursor=1\nFullScreenAllMonitors=1\nUnknownParam=7\nnoequals\n",
        "nul": hdr + b"\0\nViewOnly=1\n",
    }

TARGETS = {
    "client-msg": client_msg_seeds, "client-handshake": client_handshake_seeds,
    "server-msg": server_msg_seeds, "server-auth": server_auth_seeds,
    "hostport": hostport_seeds, "viewer-config": viewer_config_seeds,
}

if __name__ == "__main__":
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    for target, fn in TARGETS.items():
        d = os.path.join(base, target, "testsuite")
        os.makedirs(d, exist_ok=True)
        for name, data in fn().items():
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
