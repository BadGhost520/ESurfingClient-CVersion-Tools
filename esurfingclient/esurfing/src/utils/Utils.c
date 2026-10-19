#include "utils/Utils.h"

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint32_t s_rand_state = 0;

/**
 * @brief xorshift32 随机数
 * @return 随机数
 */
static uint32_t next_random()
{
    uint32_t x = s_rand_state;

    if (x == 0) x = 0x9E3779B9U;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    s_rand_state = x;
    return x;
}

void init_random()
{
    s_rand_state = (uint32_t)time(NULL) ^ (uint32_t)clock()
        ^ (uint32_t)(uintptr_t)&s_rand_state ^ 0x9E3779B9U;
    if (s_rand_state == 0) s_rand_state = 1;
}

bool read_line(char* buf, const size_t len)
{
    if (buf == NULL || len == 0) return false;

    if (fgets(buf, (int)len, stdin) == NULL)
    {
        buf[0] = '\0';
        return false;
    }

    size_t used = strlen(buf);
    if (used > 0 && buf[used - 1] == '\n')
    {
        buf[--used] = '\0';
        if (used > 0 && buf[used - 1] == '\r') buf[--used] = '\0';
    }
    else if (feof(stdin) == 0)
    {
        // 输入超过缓冲区时丢弃本行剩余内容, 避免影响下一次读取
        int c;
        while ((c = getchar()) != '\n' && c != EOF)
        {
        }
    }
    return true;
}

bool read_int(int* value)
{
    char line[64];
    char* end = NULL;
    long num;

    if (value == NULL || read_line(line, sizeof(line)) == false) return false;

    trim_str(line);
    if (line[0] == '\0') return false;

    num = strtol(line, &end, 10);
    if (end == line || *end != '\0' || num < INT_MIN || num > INT_MAX) return false;

    *value = (int)num;
    return true;
}

void trim_str(char* str)
{
    char* start;
    size_t len;

    if (str == NULL) return;

    start = str;
    while (*start != '\0' && isspace((unsigned char)*start)) start++;
    if (start != str) memmove(str, start, strlen(start) + 1);

    len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) str[--len] = '\0';
}

bool generate_uuid(char* out, const size_t len)
{
    uint8_t bytes[16];

    if (out == NULL || len < 37) return false;

    for (size_t i = 0; i < sizeof(bytes); i++) bytes[i] = (uint8_t)(next_random() & 0xFFU);

    // UUID v4: 版本号 4, variant 10xx
    bytes[6] = (uint8_t)((bytes[6] & 0x0FU) | 0x40U);
    bytes[8] = (uint8_t)((bytes[8] & 0x3FU) | 0x80U);

    snprintf(out, len,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    return true;
}
