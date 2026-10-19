#include "AlgoFinder.h"

#include "NetClient.h"
#include "cipher/CipherInterface.h"
#include "cipher/CipherUtils.h"
#include "utils/Utils.h"

#include <ctype.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * 与抓包得到的 ticket 请求保持一致。
 * POST 内容固定为零 UUID, 下面的 CDC-Checksum 就是它的 MD5。
 * 每次请求只把 Client-ID 换成新的随机 UUID, 服务端会据此返回不同的 Algo-ID。
 */
#define ALGO_TICKET_URL "http://14.146.227.141:7001/ticket.cgi?wlanuserip=172.19.211.166&wlanacip=14.148.0.67&portal_node=http://125.88.59.131:10002"
#define ALGO_TICKET_BODY "tarce log algo auto compstr null value"
_Static_assert(sizeof(ALGO_TICKET_BODY) - 1 == 38, "ticket body 长度必须是 38");
#define ALGO_ZERO_ID "00000000-0000-0000-0000-000000000000"
#define ALGO_CHECKSUM "9f89c84a559f573636a47ff8daed0d33"
#define ALGO_ACCEPT "text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*"
#define CDC_SCHOOL_ID "221"
#define CDC_DOMAIN "zsdzkd"
#define CDC_AREA "0760"

#define DEFAULT_UA "CCTP/WinSVR5/1068"
#define LINE_LEN 256
#define PROGRESS_STEP 100
#ifndef TICKET_BATCH_SIZE
#define TICKET_BATCH_SIZE 24
#endif

typedef enum
{
    FIND_MODE_COUNT = 0,
    FIND_MODE_UNTIL_NO_NEW = 1
} find_mode_t;

typedef struct
{
    char** items;
    size_t count;
    size_t capacity;
} algo_id_list_t;

static volatile sig_atomic_t s_find_stop = 0;

/**
 * @brief 查找过程收到 Ctrl+C 时只做停止标记, 由查找循环返回主菜单
 * @param sig 信号
 */
static void on_find_sigint(const int sig)
{
    (void)sig;
    s_find_stop = 1;
}

static bool is_uuid_text(const char* text, const size_t length)
{
    static const size_t hyphen_pos[] = {8, 13, 18, 23};
    size_t hyphen_i = 0;

    if (text == NULL || length != 36) return false;

    for (size_t i = 0; i < 36; i++)
    {
        if (hyphen_i < 4 && i == hyphen_pos[hyphen_i])
        {
            if (text[i] != '-') return false;
            hyphen_i++;
            continue;
        }
        if (isxdigit((unsigned char)text[i]) == 0) return false;
    }
    return hyphen_i == 4;
}

static void copy_uuid_upper(char* out, const char* src)
{
    for (size_t i = 0; i < 36; i++) out[i] = (char)toupper((unsigned char)src[i]);
    out[36] = '\0';
}

static bool read_pascal_string(const uint8_t* data, const size_t length, size_t* offset,
    const char** out, size_t* out_len)
{
    size_t str_len;

    if (data == NULL || offset == NULL || out == NULL || out_len == NULL) return false;
    if (*offset >= length) return false;

    str_len = data[*offset];
    (*offset)++;
    if (*offset + str_len > length) return false;

    *out = (const char*)(data + *offset);
    *out_len = str_len;
    *offset += str_len;
    return true;
}

/**
 * @brief 从 ticket 响应中提取 Algo-ID
 *
 * 响应头是 ZSM 格式: 3 字节头 + 两个 Pascal 字符串, 第二个字符串就是 UUID。
 * 部分通道的头部布局可能不同, 因此最后再按 UUID 文本扫描一次。
 */
static bool extract_algo_id(const char* body, const size_t body_len, char* out, const size_t out_len)
{
    const char* str1 = NULL;
    const char* str2 = NULL;
    size_t str1_len = 0;
    size_t str2_len = 0;
    size_t offset = 3;

    if (body == NULL || out == NULL || out_len < 37 || body_len < 5) return false;

    if (read_pascal_string((const uint8_t*)body, body_len, &offset, &str1, &str1_len)
        && read_pascal_string((const uint8_t*)body, body_len, &offset, &str2, &str2_len))
    {
        if (is_uuid_text(str2, str2_len))
        {
            copy_uuid_upper(out, str2);
            return true;
        }
        if (is_uuid_text(str1, str1_len))
        {
            copy_uuid_upper(out, str1);
            return true;
        }
    }

    for (size_t i = 0; i + 36 <= body_len; i++)
    {
        if (is_uuid_text(body + i, 36))
        {
            copy_uuid_upper(out, body + i);
            return true;
        }
    }
    return false;
}

static bool algo_list_add(algo_id_list_t* list, const char* id)
{
    char* copy;

    if (list == NULL || id == NULL) return false;

    for (size_t i = 0; i < list->count; i++)
    {
        if (strcmp(list->items[i], id) == 0) return false;
    }

    if (list->count == list->capacity)
    {
        const size_t new_capacity = list->capacity == 0 ? 8 : list->capacity * 2;
        char** items = realloc(list->items, new_capacity * sizeof(*items));
        if (items == NULL) return false;
        list->items = items;
        list->capacity = new_capacity;
    }

    copy = malloc(37);
    if (copy == NULL) return false;
    memcpy(copy, id, 37);
    list->items[list->count++] = copy;
    return true;
}

static void algo_list_free(algo_id_list_t* list)
{
    if (list == NULL) return;

    for (size_t i = 0; i < list->count; i++) free(list->items[i]);
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

typedef struct
{
    char ua_header[ALGO_UA_LEN + 16];
    char client_id_header[64];
    const char* headers[10];
} ticket_request_t;

static bool ticket_response_ok(const http_resp_t* resp)
{
    // 1 秒内没有响应就丢弃该请求, 不刷错误信息
    if (resp->curl_code == CURLE_OPERATION_TIMEDOUT) return false;

    if (resp->curl_code != CURLE_OK)
    {
        printf("  [错误] 请求失败: %s\n", resp->error[0] != '\0' ? resp->error : curl_easy_strerror(resp->curl_code));
        return false;
    }
    if (resp->http_code != 200)
    {
        printf("  [错误] HTTP 状态码: %ld\n", resp->http_code);
        return false;
    }
    if (resp->body_data == NULL || resp->body_size == 0)
    {
        printf("  [警告] 响应内容为空\n");
        return false;
    }
    return true;
}

static bool prepare_ticket_batch(const char* ua, ticket_request_t* reqs, http_post_item_t* items, const size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        char client_id[37];

        if (generate_uuid(client_id, sizeof(client_id)) == false) return false;

        snprintf(reqs[i].ua_header, sizeof(reqs[i].ua_header), "User-Agent: %s", ua);
        snprintf(reqs[i].client_id_header, sizeof(reqs[i].client_id_header), "Client-ID: %s", client_id);

        reqs[i].headers[0] = "CDC-Checksum: " ALGO_CHECKSUM;
        reqs[i].headers[1] = "Content-Type: application/x-www-form-urlencoded";
        reqs[i].headers[2] = reqs[i].ua_header;
        reqs[i].headers[3] = "Accept: " ALGO_ACCEPT;
        reqs[i].headers[4] = reqs[i].client_id_header;
        reqs[i].headers[5] = "Algo-ID: " ALGO_ZERO_ID;
        reqs[i].headers[6] = "CDC-SchoolId: " CDC_SCHOOL_ID;
        reqs[i].headers[7] = "CDC-Domain: " CDC_DOMAIN;
        reqs[i].headers[8] = "CDC-Area: " CDC_AREA;
        reqs[i].headers[9] = NULL;

        items[i].headers = reqs[i].headers;
        items[i].data = ALGO_TICKET_BODY;
        memset(&items[i].resp, 0, sizeof(items[i].resp));
    }
    return true;
}

bool algo_prompt_ua(char* ua, const size_t ua_len)
{
    char line[ALGO_UA_LEN];

    printf("\n常用 UA:\n");
    printf("  CCTP/WinSVR5/1068        Windows\n");
    printf("  CCTP/Linux64/1003        Linux\n");
    printf("  CCTP/android64_vpn/2093  旧 Android\n");
    printf("  CCTP/android11_64/2104   Android\n");
    printf("  CCTP/iOSdy/4023          iOS\n");
    printf("  CCTP/macdy/5019          macOS\n");
    printf("  0. 返回主菜单\n");
    printf("请输入 UA (留空使用 %s): ", DEFAULT_UA);

    if (read_line(line, sizeof(line)) == false) return false;

    trim_str(line);
    if (strcmp(line, "0") == 0) return false;
    if (line[0] == '\0') snprintf(ua, ua_len, "%s", DEFAULT_UA);
    else snprintf(ua, ua_len, "%s", line);
    return true;
}

static bool prompt_mode(const char* subject, const bool stop_after_no_new, find_mode_t* mode, size_t* count)
{
    char line[LINE_LEN];

    if (subject == NULL || mode == NULL || count == NULL) return false;

    for (;;)
    {
        printf("\n请选择查找方式:\n");
        printf("  1. 指定查找次数\n");
        if (stop_after_no_new)
        {
            printf("  2. 一直查找, 直到连续 %d 次没有新 %s\n", ALGO_FIND_NO_NEW_LIMIT, subject);
        }
        else
        {
            printf("  2. 一直查找, 不按次数停止 (Ctrl+C 停止)\n");
        }
        printf("  0. 返回主菜单\n");
        printf("请输入选项 (默认 2): ");

        if (read_line(line, sizeof(line)) == false) return false;
        trim_str(line);

        if (strcmp(line, "0") == 0) return false;

        if (line[0] == '\0' || strcmp(line, "2") == 0)
        {
            *mode = FIND_MODE_UNTIL_NO_NEW;
            *count = 0;
            return true;
        }

        if (strcmp(line, "1") == 0)
        {
            int value;

            printf("请输入查找次数 (输入 0 返回主菜单): ");
            if (read_int(&value) == false || value < 0)
            {
                printf("查找次数必须是正整数\n");
                if (feof(stdin) != 0) return false;
                continue;
            }
            if (value == 0) return false;

            *mode = FIND_MODE_COUNT;
            *count = (size_t)value;
            return true;
        }

        printf("输入无效, 请重新输入\n");
    }
}

/**
 * @brief 提示预计算法个数 (0 表示未知, 不参与提前停止)
 */
static bool prompt_expected_count(size_t* expected)
{
    char line[32];

    if (expected == NULL) return false;

    for (;;)
    {
        printf("\n预计算法个数 (0 = 未知, 不参考此项): ");
        if (read_line(line, sizeof(line)) == false) return false;

        trim_str(line);
        if (line[0] == '\0')
        {
            *expected = 0;
            return true;
        }

        char* end = NULL;
        const long value = strtol(line, &end, 10);
        if (end == line || *end != '\0' || value < 0)
        {
            printf("输入无效, 请输入非负整数\n");
            continue;
        }

        *expected = (size_t)value;
        return true;
    }
}

static void run_finder_with_ua(const char* ua)
{
    find_mode_t mode;
    size_t count = 0;
    size_t expected = 0;
    size_t attempts = 0;
    size_t no_new = 0;
    algo_id_list_t list = {0};
    void (*old_sigint)(int) = NULL;

    if (prompt_mode("Algo-ID", true, &mode, &count) == false) return;
    if (prompt_expected_count(&expected) == false) return;

    printf("\n开始查找 Algo-ID (UA: %s)\n", ua);
    if (mode == FIND_MODE_COUNT) printf("查找次数: %zu\n", count);
    else printf("连续 %d 次没有新 Algo-ID 时停止\n", ALGO_FIND_NO_NEW_LIMIT);

    s_find_stop = 0;
    old_sigint = signal(SIGINT, on_find_sigint);
    if (old_sigint != SIG_ERR) printf("查找中按 Ctrl+C 可停止并返回主菜单\n");

    size_t last_progress = 0;

    for (;;)
    {
        ticket_request_t reqs[TICKET_BATCH_SIZE];
        http_post_item_t items[TICKET_BATCH_SIZE];
        size_t batch_count = TICKET_BATCH_SIZE;
        bool stop_batch = false;

        if (s_find_stop != 0) break;
        if (mode == FIND_MODE_COUNT && attempts >= count) break;
        if (mode == FIND_MODE_UNTIL_NO_NEW && no_new >= ALGO_FIND_NO_NEW_LIMIT) break;
        if (expected > 0 && list.count >= expected) break;

        if (mode == FIND_MODE_COUNT)
        {
            const size_t remaining = count - attempts;
            if (batch_count > remaining) batch_count = remaining;
        }

        if (expected > 0)
        {
            const size_t remaining_expected = expected - list.count;
            if (batch_count > remaining_expected) batch_count = remaining_expected;
        }

        if (batch_count == 0) break;
        if (prepare_ticket_batch(ua, reqs, items, batch_count) == false) break;

        http_post_batch(ALGO_TICKET_URL, items, batch_count, TICKET_BATCH_SIZE);

        for (size_t i = 0; i < batch_count; i++)
        {
            char id[ALGO_ID_LEN];

            attempts++;

            if (ticket_response_ok(&items[i].resp))
            {
                if (extract_algo_id(items[i].resp.body_data, items[i].resp.body_size, id, sizeof(id)))
                {
                    if (algo_list_add(&list, id))
                    {
                        no_new = 0;
                        printf("  [新] #%zu %s (第 %zu 次)\n", list.count, id, attempts);
                    }
                    else
                    {
                        no_new++;
                    }
                }
                else
                {
                    printf("  [警告] 响应中没有 Algo-ID\n");
                    no_new++;
                }
            }
            else
            {
                no_new++;
            }

            http_resp_free(&items[i].resp);

            if ((mode == FIND_MODE_UNTIL_NO_NEW && no_new >= ALGO_FIND_NO_NEW_LIMIT)
                || (expected > 0 && list.count >= expected)
                || s_find_stop != 0)
            {
                stop_batch = true;
            }

            if (stop_batch)
            {
                for (size_t j = i + 1; j < batch_count; j++) http_resp_free(&items[j].resp);
                break;
            }
        }

        if (attempts / PROGRESS_STEP > last_progress)
        {
            last_progress = attempts / PROGRESS_STEP;
            printf("  ... 已查找 %zu 次, 共发现 %zu 个 Algo-ID\n", attempts, list.count);
        }

        if (stop_batch) break;
    }

    if (old_sigint != SIG_ERR) signal(SIGINT, old_sigint);
    if (s_find_stop != 0) printf("\n已停止查找\n");
    if (expected > 0 && list.count >= expected) printf("\n已达到预计算法个数: %zu\n", expected);

    printf("\n查找结束: 共查找 %zu 次, 发现 %zu 个 Algo-ID\n", attempts, list.count);
    if (list.count == 0)
    {
        printf("未找到 Algo-ID, 请检查 UA 与网络\n");
    }
    else
    {
        for (size_t i = 0; i < list.count; i++) printf("  %zu. %s\n", i + 1, list.items[i]);
    }

    algo_list_free(&list);
}

bool algo_fetch_matching_zsm(const char* ua, const char* target_algo_id, const size_t max_attempts,
    char** out_body, size_t* out_size)
{
    size_t attempts = 0;
    bool found = false;
    void (*old_sigint)(int) = NULL;

    if (ua == NULL || target_algo_id == NULL || out_body == NULL || out_size == NULL) return false;

    *out_body = NULL;
    *out_size = 0;

    printf("\n开始查找匹配的 Algo-ID: %s\n", target_algo_id);
    if (max_attempts > 0) printf("最多查找 %zu 次\n", max_attempts);
    else printf("一直查找, 按 Ctrl+C 停止\n");

    s_find_stop = 0;
    old_sigint = signal(SIGINT, on_find_sigint);
    if (old_sigint != SIG_ERR) printf("查找中按 Ctrl+C 可停止并返回主菜单\n");
    printf("每次查找到的 Algo-ID:\n");

    for (;;)
    {
        ticket_request_t reqs[TICKET_BATCH_SIZE];
        http_post_item_t items[TICKET_BATCH_SIZE];
        size_t batch_count = TICKET_BATCH_SIZE;
        bool stop_batch = false;

        if (s_find_stop != 0) break;
        if (max_attempts > 0 && attempts >= max_attempts) break;

        if (max_attempts > 0)
        {
            const size_t remaining = max_attempts - attempts;
            if (batch_count > remaining) batch_count = remaining;
        }

        if (batch_count == 0) break;
        if (prepare_ticket_batch(ua, reqs, items, batch_count) == false) break;

        http_post_batch(ALGO_TICKET_URL, items, batch_count, TICKET_BATCH_SIZE);

        for (size_t i = 0; i < batch_count; i++)
        {
            char id[ALGO_ID_LEN];

            attempts++;

            if (ticket_response_ok(&items[i].resp))
            {
                if (extract_algo_id(items[i].resp.body_data, items[i].resp.body_size, id, sizeof(id)))
                {
                    if (strcmp(id, target_algo_id) == 0)
                    {
                        *out_body = items[i].resp.body_data;
                        *out_size = items[i].resp.body_size;
                        items[i].resp.body_data = NULL;
                        items[i].resp.body_size = 0;
                        printf("  [匹配] %s (第 %zu 次), ZSM 大小: %zu\n", id, attempts, *out_size);
                        found = true;
                    }
                    else
                    {
                        printf("  [%zu] %s\n", attempts, id);
                    }
                }
                else
                {
                    printf("  [%zu] 响应中没有 Algo-ID\n", attempts);
                }
            }
            else if (items[i].resp.curl_code == CURLE_OPERATION_TIMEDOUT)
            {
                printf("  [%zu] 请求超时, 已丢弃\n", attempts);
            }

            http_resp_free(&items[i].resp);

            if (found || s_find_stop != 0)
            {
                stop_batch = true;
            }

            if (stop_batch)
            {
                for (size_t j = i + 1; j < batch_count; j++) http_resp_free(&items[j].resp);
                break;
            }
        }

        if (stop_batch) break;
    }

    if (old_sigint != SIG_ERR) signal(SIGINT, old_sigint);

    if (found == false)
    {
        if (s_find_stop != 0) printf("\n已停止查找\n");
        else printf("\n已查找 %zu 次, 未找到匹配的 Algo-ID\n", attempts);
    }

    return found;
}

#define KEY_IV_DEFAULT_FILE "key_iv.txt"
#define KEY_IV_PATH_LEN 512
#define KEY_IV_LINE_LEN 512
#define KEY_HEX_LEN (ZSM_KEY_MAX_LEN * 2 + 1)
#define IV_HEX_LEN (ZSM_IV_MAX_LEN * 2 + 1)

typedef struct
{
    char** items;
    size_t count;
    size_t capacity;
} string_set_t;

static bool string_set_contains(const string_set_t* set, const char* value)
{
    if (set == NULL || value == NULL) return false;

    for (size_t i = 0; i < set->count; i++)
    {
        if (strcmp(set->items[i], value) == 0) return true;
    }
    return false;
}

static bool string_set_add(string_set_t* set, const char* value)
{
    char* copy;

    if (set == NULL || value == NULL) return false;
    if (string_set_contains(set, value)) return true;

    if (set->count == set->capacity)
    {
        const size_t new_capacity = set->capacity == 0 ? 16 : set->capacity * 2;
        char** items = realloc(set->items, new_capacity * sizeof(*items));
        if (items == NULL) return false;
        set->items = items;
        set->capacity = new_capacity;
    }

    copy = malloc(strlen(value) + 1);
    if (copy == NULL) return false;
    strcpy(copy, value);
    set->items[set->count++] = copy;
    return true;
}

static void string_set_free(string_set_t* set)
{
    if (set == NULL) return;

    for (size_t i = 0; i < set->count; i++) free(set->items[i]);
    free(set->items);
    set->items = NULL;
    set->count = 0;
    set->capacity = 0;
}

/**
 * @brief 从已有导出文件中读取 Algo-ID, 用于跨次运行去重
 */
static void load_existing_ids(const char* path, string_set_t* set)
{
    const char* prefix = "Algo-ID: ";
    const size_t prefix_len = strlen(prefix);
    char line[KEY_IV_LINE_LEN];
    FILE* fp = fopen(path, "r");

    if (fp == NULL) return;

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        if (strncmp(line, prefix, prefix_len) == 0)
        {
            char* id = line + prefix_len;
            trim_str(id);
            if (id[0] != '\0') string_set_add(set, id);
        }
    }
    fclose(fp);

    if (set->count > 0)
    {
        printf("已从文件加载 %zu 个已有 Algo-ID, 重复项将跳过\n", set->count);
    }
}

/**
 * @brief 判断 Algo-ID 是否属于固定算法表
 */
static bool is_fixed_algo_id(const char* algo_id)
{
    return is_fixed_cipher(algo_id);
}

/**
 * @brief 从动态 ZSM 中解析 key/iv 并转成十六进制
 */
static bool parse_key_iv_from_zsm(const char* ua, const uint8_t* body, const size_t body_len,
    char* key_hex, const size_t key_hex_size, char* iv_hex, const size_t iv_hex_size,
    int8_t* type_out)
{
    uint8_t key[ZSM_KEY_MAX_LEN] = {0};
    uint8_t iv[ZSM_IV_MAX_LEN] = {0};
    size_t key_len = 0;
    size_t iv_len = 0;
    int8_t cdy = -1;
    bool ok;

    if (type_out != NULL) *type_out = -1;

    if (strstr(ua, "WinSVR") != NULL)
    {
        ok = get_win_zsm_key_iv(body, body_len, NULL, key, &key_len, iv, &iv_len, &cdy);
    }
    else if (strstr(ua, "iOSdy") != NULL || strstr(ua, "macdy") != NULL)
    {
        ok = get_ios_zsm_key_iv(body, body_len, NULL, key, &key_len, iv, &iv_len, &cdy);
    }
    else
    {
        return false;
    }

    if (ok == false || key_len == 0) return false;

    char* key_text = bytes_2_hex(key, key_len);
    if (key_text == NULL) return false;
    snprintf(key_hex, key_hex_size, "%s", key_text);
    free(key_text);

    if (iv_len > 0)
    {
        char* iv_text = bytes_2_hex(iv, iv_len);
        if (iv_text == NULL) return false;
        snprintf(iv_hex, iv_hex_size, "%s", iv_text);
        free(iv_text);
    }
    else
    {
        snprintf(iv_hex, iv_hex_size, "%s", "(none)");
    }

    if (type_out != NULL) *type_out = cdy;
    return true;
}

static const char* zsm_platform_name(const char* ua)
{
    if (strstr(ua, "WinSVR") != NULL) return "Windows";
    if (strstr(ua, "macdy") != NULL) return "macOS";
    if (strstr(ua, "iOSdy") != NULL) return "iOS";
    return "Unknown";
}

static void format_type_text(const int8_t type, char* buf, const size_t len)
{
    if (type >= 0) snprintf(buf, len, "%d", type);
    else snprintf(buf, len, "unknown");
}

static bool write_key_iv_entry(FILE* fp, const size_t index, const char* platform, const int8_t type,
    const char* id, const char* key_hex, const char* iv_hex)
{
    char type_text[16];

    if (fp == NULL) return false;

    format_type_text(type, type_text, sizeof(type_text));
    if (fprintf(fp, "Index: %zu\nPlatform: %s\nType: %s\nAlgo-ID: %s\nKey: %s\nIV: %s\n\n",
            index, platform, type_text, id, key_hex, iv_hex) < 0)
    {
        return false;
    }
    fflush(fp);
    return true;
}

static void run_key_iv_with_ua(const char* ua)
{
    char path[KEY_IV_PATH_LEN];
    find_mode_t mode;
    size_t count = 0;
    size_t expected = 0;
    size_t attempts = 0;
    size_t exported = 0;
    size_t total_entries = 0;
    size_t last_progress = 0;
    string_set_t seen = {0};
    FILE* fp = NULL;
    void (*old_sigint)(int) = NULL;

    if (prompt_mode("key/iv", false, &mode, &count) == false) return;
    if (prompt_expected_count(&expected) == false) return;

    printf("\n请输入导出文件名 (直接回车默认 %s): ", KEY_IV_DEFAULT_FILE);
    if (read_line(path, sizeof(path)) == false) return;
    trim_str(path);
    if (path[0] == '\0') snprintf(path, sizeof(path), "%s", KEY_IV_DEFAULT_FILE);

    load_existing_ids(path, &seen);
    total_entries = seen.count;
    if (expected > 0 && total_entries > 0)
    {
        printf("预计算法个数按文件总条数计算, 当前已有 %zu 条\n", total_entries);
    }

    fp = fopen(path, "a");
    if (fp == NULL)
    {
        printf("无法打开文件: %s\n", path);
        string_set_free(&seen);
        return;
    }

    fseek(fp, 0, SEEK_END);
    if (ftell(fp) == 0)
    {
        fprintf(fp, "# Index / Platform / Type / Algo-ID / Key / IV\n\n");
        fflush(fp);
    }

    printf("\n开始获取 Key/IV (UA: %s)\n", ua);
    if (mode == FIND_MODE_COUNT) printf("查找次数: %zu\n", count);
    else printf("一直查找, 不按次数停止 (Ctrl+C 停止)\n");

    if (strstr(ua, "WinSVR") == NULL && strstr(ua, "iOSdy") == NULL && strstr(ua, "macdy") == NULL)
    {
        printf("提示: 该 UA 返回固定算法, ZSM 中没有可解析的 key/iv, 建议使用 Windows/iOS/macOS UA\n");
    }

    s_find_stop = 0;
    old_sigint = signal(SIGINT, on_find_sigint);
    if (old_sigint != SIG_ERR) printf("查找中按 Ctrl+C 可停止并返回主菜单\n");

    for (;;)
    {
        ticket_request_t reqs[TICKET_BATCH_SIZE];
        http_post_item_t items[TICKET_BATCH_SIZE];
        size_t batch_count = TICKET_BATCH_SIZE;
        bool stop_batch = false;

        if (s_find_stop != 0) break;
        if (mode == FIND_MODE_COUNT && attempts >= count) break;
        if (expected > 0 && total_entries >= expected) break;

        if (mode == FIND_MODE_COUNT)
        {
            const size_t remaining = count - attempts;
            if (batch_count > remaining) batch_count = remaining;
        }

        if (expected > 0)
        {
            const size_t remaining_expected = expected - total_entries;
            if (batch_count > remaining_expected) batch_count = remaining_expected;
        }

        if (batch_count == 0) break;
        if (prepare_ticket_batch(ua, reqs, items, batch_count) == false) break;

        http_post_batch(ALGO_TICKET_URL, items, batch_count, TICKET_BATCH_SIZE);

        for (size_t i = 0; i < batch_count; i++)
        {
            char id[ALGO_ID_LEN];

            attempts++;

            if (ticket_response_ok(&items[i].resp))
            {
                if (extract_algo_id(items[i].resp.body_data, items[i].resp.body_size, id, sizeof(id)))
                {
                    if (string_set_contains(&seen, id) == false)
                    {
                        char key_hex[KEY_HEX_LEN];
                        char iv_hex[IV_HEX_LEN];
                        char type_text[16];
                        int8_t cdy = -1;

                        if (parse_key_iv_from_zsm(ua, (const uint8_t*)items[i].resp.body_data,
                                items[i].resp.body_size, key_hex, sizeof(key_hex), iv_hex, sizeof(iv_hex), &cdy))
                        {
                            const char* platform = zsm_platform_name(ua);
                            format_type_text(cdy, type_text, sizeof(type_text));

                            if (write_key_iv_entry(fp, total_entries + 1, platform, cdy, id, key_hex, iv_hex) == false)
                            {
                                printf("  [错误] 写入文件失败: %s\n", path);
                            }
                            else
                            {
                                string_set_add(&seen, id);
                                exported++;
                                total_entries++;
                                printf("  [新] #%zu %s\n       Platform: %s\n       Type: %s\n       Key: %s\n       IV: %s\n",
                                    total_entries, id, platform, type_text, key_hex, iv_hex);
                            }
                        }
                        else if (is_fixed_algo_id(id))
                        {
                            string_set_add(&seen, id);
                            printf("  [跳过] %s (固定算法, key/iv 在代码中)\n", id);
                        }
                        else
                        {
                            printf("  [失败] %s (动态 ZSM 解析失败, 稍后重试)\n", id);
                        }
                    }
                }
                else
                {
                    printf("  [警告] 响应中没有 Algo-ID\n");
                }
            }
            http_resp_free(&items[i].resp);

            if ((expected > 0 && total_entries >= expected) || s_find_stop != 0)
            {
                stop_batch = true;
            }

            if (stop_batch)
            {
                for (size_t j = i + 1; j < batch_count; j++) http_resp_free(&items[j].resp);
                break;
            }
        }

        if (attempts / PROGRESS_STEP > last_progress)
        {
            last_progress = attempts / PROGRESS_STEP;
            printf("  ... 已查找 %zu 次, 已导出 %zu 条\n", attempts, exported);
        }

        if (stop_batch) break;
    }

    if (old_sigint != SIG_ERR) signal(SIGINT, old_sigint);
    if (s_find_stop != 0) printf("\n已停止获取\n");
    if (expected > 0 && total_entries >= expected) printf("\n已达到预计算法个数: %zu\n", expected);

    fclose(fp);
    printf("\n获取结束: 共查找 %zu 次, 导出 %zu 条, 文件: %s\n", attempts, exported, path);
    string_set_free(&seen);
}

/**
 * @brief 询问是否导出 Key/IV 等信息
 */
static bool prompt_export_switch(bool* export_key_iv)
{
    char line[16];

    if (export_key_iv == NULL) return false;

    for (;;)
    {
        printf("\n是否导出 Key/IV 等信息? (y/N): ");
        if (read_line(line, sizeof(line)) == false) return false;

        trim_str(line);
        if (line[0] == '\0' || (line[1] == '\0' && (line[0] == 'n' || line[0] == 'N')))
        {
            *export_key_iv = false;
            return true;
        }
        if (line[1] == '\0' && (line[0] == 'y' || line[0] == 'Y'))
        {
            *export_key_iv = true;
            return true;
        }

        printf("输入无效, 请输入 y 或 n\n");
    }
}

void algo_finder_run(void)
{
    char ua[ALGO_UA_LEN];
    bool export_key_iv = false;

    if (algo_prompt_ua(ua, sizeof(ua)) == false) return;
    if (prompt_export_switch(&export_key_iv) == false) return;

    if (export_key_iv) run_key_iv_with_ua(ua);
    else run_finder_with_ua(ua);
}
