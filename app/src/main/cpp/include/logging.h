#pragma once

#include <cerrno>
#include <cstring>

#ifdef __ANDROID__
#include <android/log.h>
#define TAG "LSPosedFuseFixer"
#define LOGI(...) (__android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__))
#define LOGW(...) (__android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__))
#define LOGE(...) (__android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__))
#define PLOGE(fmt, ...) (__android_log_print(ANDROID_LOG_ERROR, TAG, "failed with %d %s: " fmt, errno, strerror(errno) __VA_OPT__(,) __VA_ARGS__))
#ifdef NDEBUG
#define LOGV(...)
#define LOGD(...)
#else
#define DEBUG 1
#define LOGV(...) (__android_log_print(ANDROID_LOG_VERBOSE, TAG, __VA_ARGS__))
#define LOGD(...) (__android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__))
#endif
#else
#include <cstdio>
#define LOGI(...) do { std::fprintf(stderr, __VA_ARGS__); std::fputc('\n', stderr); } while (0)
#define LOGW(...) do { std::fprintf(stderr, __VA_ARGS__); std::fputc('\n', stderr); } while (0)
#define LOGE(...) do { std::fprintf(stderr, __VA_ARGS__); std::fputc('\n', stderr); } while (0)
#define PLOGE(fmt, ...) do { std::fprintf(stderr, "failed with %d %s: " fmt "\n", errno, std::strerror(errno) __VA_OPT__(,) __VA_ARGS__); } while (0)
#define LOGV(...)
#define LOGD(...)
#endif
