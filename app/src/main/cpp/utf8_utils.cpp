#include "utf8_utils.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <limits>

#include <unicode/utf8.h>

namespace {
bool is_default_ignorable_code_point(UChar32 ch) {
    return ch == 0x00AD || ch == 0x034F || ch == 0x061C ||
           (0x115F <= ch && ch <= 0x1160) ||
           (0x17B4 <= ch && ch <= 0x17B5) ||
           (0x180B <= ch && ch <= 0x180E) ||
           (0x200B <= ch && ch <= 0x200F) ||
           (0x202A <= ch && ch <= 0x202E) ||
           (0x2060 <= ch && ch <= 0x206F) ||
           ch == 0x3164 ||
           (0xFE00 <= ch && ch <= 0xFE0F) ||
           ch == 0xFEFF || ch == 0xFFA0 ||
           (0xFFF0 <= ch && ch <= 0xFFF8) ||
           (0x1BCA0 <= ch && ch <= 0x1BCA3) ||
           (0x1D173 <= ch && ch <= 0x1D17A) ||
           (0xE0000 <= ch && ch <= 0xE0FFF);
}

inline uint8_t fold_ascii(uint8_t value) {
    return value >= 'A' && value <= 'Z'
            ? static_cast<uint8_t>(value + ('a' - 'A')) : value;
}

std::string normalize(std::string_view input) {
    if (input.size() > static_cast<size_t>(INT32_MAX))
        return std::string(input);
    std::string output;
    output.reserve(input.size());
    const auto *bytes = reinterpret_cast<const uint8_t *>(input.data());
    const int32_t length = static_cast<int32_t>(input.size());
    int32_t index = 0;
    while (index < length) {
        const int32_t start = index;
        UChar32 code_point = 0;
        U8_NEXT(bytes, index, length, code_point);
        if (code_point < 0 || !is_default_ignorable_code_point(code_point)) {
            output.append(input.data() + start,
                          static_cast<size_t>(index - start));
        }
    }
    return output;
}
} // namespace

int svcasecmp_fix(std::string_view lhs, std::string_view rhs) {
    const std::string left = normalize(lhs);
    const std::string right = normalize(rhs);
    const size_t common = std::min(left.size(), right.size());
    for (size_t i = 0; i < common; ++i) {
        const uint8_t a = fold_ascii(static_cast<uint8_t>(left[i]));
        const uint8_t b = fold_ascii(static_cast<uint8_t>(right[i]));
        if (a != b) return static_cast<int>(a) - static_cast<int>(b);
    }
    if (left.size() == right.size()) return 0;
    return left.size() < right.size() ? -1 : 1;
}

int strcasecmp_fix(const char *lhs, const char *rhs) {
    if (!lhs || !rhs) return lhs == rhs ? 0 : (lhs ? 1 : -1);
    return svcasecmp_fix(std::string_view(lhs, strlen(lhs)),
                         std::string_view(rhs, strlen(rhs)));
}

bool has_default_ignorable_code_point(const std::string &value) {
    if (value.size() > static_cast<size_t>(INT32_MAX)) return false;
    const auto *bytes = reinterpret_cast<const uint8_t *>(value.data());
    const int32_t length = static_cast<int32_t>(value.size());
    int32_t index = 0;
    while (index < length) {
        UChar32 code_point = 0;
        U8_NEXT(bytes, index, length, code_point);
        if (code_point >= 0 && is_default_ignorable_code_point(code_point))
            return true;
    }
    return false;
}

void remove_default_ignorable_code_point(std::string &value) {
    if (value.size() > static_cast<size_t>(INT32_MAX)) return;
    auto *bytes = reinterpret_cast<uint8_t *>(value.data());
    const int32_t length = static_cast<int32_t>(value.size());
    int32_t read = 0;
    size_t write = 0;
    while (read < length) {
        const int32_t start = read;
        UChar32 code_point = 0;
        U8_NEXT(bytes, read, length, code_point);
        if (code_point < 0 || !is_default_ignorable_code_point(code_point)) {
            const size_t count = static_cast<size_t>(read - start);
            if (write != static_cast<size_t>(start))
                memmove(bytes + write, bytes + start, count);
            write += count;
        }
    }
    value.resize(write);
}

int utf16ToStandardUtf8(const char16_t *input, size_t length, std::string *output) {
    if (!output || (!input && length != 0)) return EINVAL;
    output->clear();
    if (length > SIZE_MAX / 3) return ENAMETOOLONG;

    std::string encoded;
    encoded.reserve(length * 3);
    for (size_t i = 0; i < length; ++i) {
        uint32_t code_point = input[i];
        if (code_point >= 0xD800 && code_point <= 0xDBFF) {
            if (i + 1 >= length) return EILSEQ;
            const uint32_t low = input[++i];
            if (low < 0xDC00 || low > 0xDFFF) return EILSEQ;
            code_point = 0x10000 + ((code_point - 0xD800) << 10) +
                         (low - 0xDC00);
        } else if (code_point >= 0xDC00 && code_point <= 0xDFFF) {
            return EILSEQ;
        }
        // POSIX paths are NUL-terminated byte strings; embedded U+0000
        // would silently truncate the path at the native boundary.
        if (code_point == 0) return EINVAL;
        if (code_point <= 0x7F) {
            encoded.push_back(static_cast<char>(code_point));
        } else if (code_point <= 0x7FF) {
            encoded.push_back(static_cast<char>(0xC0 | (code_point >> 6)));
            encoded.push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
        } else if (code_point <= 0xFFFF) {
            encoded.push_back(static_cast<char>(0xE0 | (code_point >> 12)));
            encoded.push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3F)));
            encoded.push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
        } else if (code_point <= 0x10FFFF) {
            encoded.push_back(static_cast<char>(0xF0 | (code_point >> 18)));
            encoded.push_back(static_cast<char>(0x80 | ((code_point >> 12) & 0x3F)));
            encoded.push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3F)));
            encoded.push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
        } else {
            return EILSEQ;
        }
    }
    output->swap(encoded);
    return 0;
}
