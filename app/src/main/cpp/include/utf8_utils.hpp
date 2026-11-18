#pragma once

#include <string>
#include <string_view>

int svcasecmp_fix(std::string_view lhs, std::string_view rhs);
int strcasecmp_fix(const char *lhs, const char *rhs);
bool has_default_ignorable_code_point(const std::string &value);
void remove_default_ignorable_code_point(std::string &value);
