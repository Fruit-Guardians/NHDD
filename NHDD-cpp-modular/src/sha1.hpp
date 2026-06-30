// sha1.hpp — SHA-1 hash implementation (header-only)
#pragma once

#include <cstdint>
#include <cstring>
#include <cstddef>

class SHA1 {
public:
    SHA1() { init(); }

    void init() {
        state_[0] = 0x67452301;
        state_[1] = 0xEFCDAB89;
        state_[2] = 0x98BADCFE;
        state_[3] = 0x10325476;
        state_[4] = 0xC3D2E1F0;
        count_ = 0;
    }

    void update(const uint8_t* data, size_t len) {
        size_t idx = static_cast<size_t>(count_ % 64);
        count_ += len;
        size_t i = 0;
        if (idx) {
            size_t need = 64 - idx;
            if (len < need) {
                std::memcpy(buffer_ + idx, data, len);
                return;
            }
            std::memcpy(buffer_ + idx, data, need);
            transform(buffer_);
            i = need;
        }
        for (; i + 64 <= len; i += 64)
            transform(data + i);
        if (i < len)
            std::memcpy(buffer_ + idx, data + i, len - i);
    }

    void final(uint8_t digest[20]) {
        uint64_t bits = count_ * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while ((count_ % 64) != 56)
            update(&zero, 1);
        uint8_t len_be[8];
        for (int i = 0; i < 8; i++)
            len_be[i] = static_cast<uint8_t>(bits >> (56 - i * 8));
        update(len_be, 8);
        for (int i = 0; i < 5; i++) {
            digest[i * 4]     = static_cast<uint8_t>(state_[i] >> 24);
            digest[i * 4 + 1] = static_cast<uint8_t>(state_[i] >> 16);
            digest[i * 4 + 2] = static_cast<uint8_t>(state_[i] >> 8);
            digest[i * 4 + 3] = static_cast<uint8_t>(state_[i]);
        }
    }

private:
    static constexpr inline uint32_t ROL(uint32_t v, int n) {
        return (v << n) | (v >> (32 - n));
    }

    void transform(const uint8_t* block) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++)
            w[i] = (static_cast<uint32_t>(block[i*4]) << 24) |
                   (static_cast<uint32_t>(block[i*4+1]) << 16) |
                   (static_cast<uint32_t>(block[i*4+2]) << 8) |
                   static_cast<uint32_t>(block[i*4+3]);
        for (int i = 16; i < 80; i++)
            w[i] = ROL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

        uint32_t a = state_[0], b = state_[1], c = state_[2];
        uint32_t d = state_[3], e = state_[4];

        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | (~b & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            uint32_t tmp = ROL(a, 5) + f + e + k + w[i];
            e = d; d = c; c = ROL(b, 30); b = a; a = tmp;
        }
        state_[0] += a; state_[1] += b; state_[2] += c;
        state_[3] += d; state_[4] += e;
    }

    uint32_t state_[5];
    uint64_t count_;
    uint8_t  buffer_[64];
};
