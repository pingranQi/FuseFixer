#pragma once

#include <string>
#include <string_view>

int svcasecmp_fix(std::string_view lhs, std::string_view rhs);
int strcasecmp_fix(const char *lhs, const char *rhs);
bool has_default_ignorable_code_point(const std::string &value);
void remove_default_ignorable_code_point(std::string &value);

// Converts UTF-16 code units to strict, standard UTF-8. Returns an errno value.
int utf16ToStandardUtf8(const char16_t *input, size_t length, std::string *output);
