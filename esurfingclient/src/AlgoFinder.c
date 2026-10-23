#include "AlgoFinder.h"

#include "NetClient.h"
#include "cipher/CipherInterface.h"
#include "cipher/CipherUtils.h"
#include "utils/Utils.h"
#include "utils/sim/SimEvp.h"

#include <ctype.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * 与抓包得到的 ticket 请求保持一致。
 * 查找 Algo-ID 时 POST 38 字节说明串；Ticket 检查首次拉 ZSM 时用零 UUID
 * (iOS/macOS 用空 body)，CDC-Checksum 对应为下面常量的 MD5。
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

const char* algo_ticket_url(void)
{
    return ALGO_TICKET_URL;
}

typedef enum
{
    FIND_MODE_COUNT = 0,
    FIND_MODE_UNTIL_NO_NEW = 1
} find_mode_t;

typedef struct
{
    char* id;
    unsigned server_mask; /* bit0: 14.146.227.141, bit1: 121.8.177.212 */
} algo_entry_t;

typedef struct
{
    algo_entry_t* items;
    size_t count;
    size_t capacity;
} algo_id_list_t;

typedef struct
{
    const char* name;
    const char* url;
} algo_server_t;

/* 功能 2 使用的两个认证服务器；交错发送 */
static const algo_server_t ALGO_SERVERS[] = {
    {
        "14.146.227.141",
        "http://14.146.227.141:7001/ticket.cgi?wlanuserip=172.19.217.66&wlanacip=14.148.0.67"
    },
    {
        "121.8.177.212",
        "http://121.8.177.212:7001/ticket.cgi?wlanuserip=172.19.221.13&wlanacip=14.148.0.67"
    }
};

#define ALGO_SERVER_COUNT (sizeof(ALGO_SERVERS) / sizeof(ALGO_SERVERS[0]))

const char* algo_ticket_url_alt(void)
{
    return ALGO_SERVERS[1].url;
}

const char* algo_server_name(const size_t index)
{
    if (index >= ALGO_SERVER_COUNT) return "UNKNOWN";
    return ALGO_SERVERS[index].name;
}

const char* algo_server_url(const size_t index)
{
    if (index >= ALGO_SERVER_COUNT) return NULL;
    return ALGO_SERVERS[index].url;
}

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

/* 返回 0=同服务器重复, 1=新 Algo-ID, 2=已有 ID 但新服务器 */
static int algo_list_add(algo_id_list_t* list, const char* id, const unsigned server_mask)
{
    char* copy;

    if (list == NULL || id == NULL) return 0;

    for (size_t i = 0; i < list->count; i++)
    {
        if (strcmp(list->items[i].id, id) == 0)
        {
            if ((list->items[i].server_mask & server_mask) == server_mask) return 0;
            list->items[i].server_mask |= server_mask;
            return 2;
        }
    }

    if (list->count == list->capacity)
    {
        const size_t new_capacity = list->capacity == 0 ? 8 : list->capacity * 2;
        algo_entry_t* items = realloc(list->items, new_capacity * sizeof(*items));
        if (items == NULL) return 0;
        list->items = items;
        list->capacity = new_capacity;
    }

    copy = malloc(37);
    if (copy == NULL) return 0;
    memcpy(copy, id, 37);
    list->items[list->count].id = copy;
    list->items[list->count].server_mask = server_mask;
    list->count++;
    return 1;
}

static void algo_list_free(algo_id_list_t* list)
{
    if (list == NULL) return;

    for (size_t i = 0; i < list->count; i++) free(list->items[i].id);
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static const char* server_source_label(const unsigned mask)
{
    if ((mask & 3u) == 3u) return "BOTH";
    if (mask & 1u) return ALGO_SERVERS[0].name;
    if (mask & 2u) return ALGO_SERVERS[1].name;
    return "UNKNOWN";
}

typedef struct
{
    char ua_header[ALGO_UA_LEN + 16];
    char client_id_header[64];
    char client_id[37];
    char checksum_header[64];
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

static bool prepare_ticket_batch(const char* ua, const char* body, const char* checksum,
    ticket_request_t* reqs, http_post_item_t* items, const size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        char client_id[37];

        if (generate_uuid(client_id, sizeof(client_id)) == false) return false;

        snprintf(reqs[i].client_id, sizeof(reqs[i].client_id), "%s", client_id);
        snprintf(reqs[i].ua_header, sizeof(reqs[i].ua_header), "User-Agent: %s", ua);
        snprintf(reqs[i].client_id_header, sizeof(reqs[i].client_id_header), "Client-ID: %s", client_id);
        snprintf(reqs[i].checksum_header, sizeof(reqs[i].checksum_header), "CDC-Checksum: %s", checksum);

        reqs[i].headers[0] = reqs[i].checksum_header;
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
        items[i].data = body;
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

static bool prompt_mode(const char* subject, find_mode_t* mode, size_t* count)
{
    char line[LINE_LEN];

    if (subject == NULL || mode == NULL || count == NULL) return false;

    for (;;)
    {
        printf("\n请选择查找方式:\n");
        printf("  1. 指定查找次数\n");
        printf("  2. 一直查找, 不按次数停止 (Ctrl+C 停止)\n");
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
    size_t batch_no = 0;
    algo_id_list_t list = {0};
    void (*old_sigint)(int) = NULL;
    char path[128];

    if (prompt_mode("Algo-ID", &mode, &count) == false) return;
    if (prompt_expected_count(&expected) == false) return;

    printf("\n请输入导出文件名 (直接回车默认 algo_ids.txt): ");
    if (read_line(path, sizeof(path)) == false) return;
    trim_str(path);
    if (path[0] == '\0') snprintf(path, sizeof(path), "%s", "algo_ids.txt");

    printf("\n开始查找 Algo-ID (UA: %s)\n", ua);
    printf("服务器: %s <-> %s (交错请求)\n", ALGO_SERVERS[0].name, ALGO_SERVERS[1].name);
    if (mode == FIND_MODE_COUNT) printf("查找次数: %zu\n", count);
    else printf("一直查找, 不按次数停止 (Ctrl+C 停止)\n");

    s_find_stop = 0;
    old_sigint = signal(SIGINT, on_find_sigint);
    if (old_sigint != SIG_ERR) printf("查找中按 Ctrl+C 可停止并导出已发现结果\n");

    size_t last_progress = 0;

    for (;;)
    {
        ticket_request_t reqs[TICKET_BATCH_SIZE];
        http_post_item_t items[TICKET_BATCH_SIZE];
        size_t batch_count = TICKET_BATCH_SIZE;
        bool stop_batch = false;
        const algo_server_t* server;

        if (s_find_stop != 0) break;
        if (mode == FIND_MODE_COUNT && attempts >= count) break;
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
        if (prepare_ticket_batch(ua, ALGO_TICKET_BODY, ALGO_CHECKSUM, reqs, items, batch_count) == false) break;

        server = &ALGO_SERVERS[batch_no % ALGO_SERVER_COUNT];
        const unsigned server_mask = 1u << (batch_no % ALGO_SERVER_COUNT);
        batch_no++;

        http_post_batch(server->url, items, batch_count, TICKET_BATCH_SIZE);

        for (size_t i = 0; i < batch_count; i++)
        {
            char id[ALGO_ID_LEN];

            attempts++;

            if (ticket_response_ok(&items[i].resp))
            {
                if (extract_algo_id(items[i].resp.body_data, items[i].resp.body_size, id, sizeof(id)))
                {
                    const int added = algo_list_add(&list, id, server_mask);
                    if (added == 1)
                    {
                        printf("  [新] #%zu %s [%s] (第 %zu 次)\n",
                            list.count, id, server->name, attempts);
                    }
                    else if (added == 2)
                    {
                        printf("  [同ID新服务器] %s [%s] (第 %zu 次)\n",
                            id, server->name, attempts);
                    }
                }
                else
                {
                    printf("  [警告] 响应中没有 Algo-ID [%s]\n", server->name);
                }
            }

            http_resp_free(&items[i].resp);

            if ((expected > 0 && list.count >= expected) || s_find_stop != 0)
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

    {
        FILE* fp = fopen(path, "w");
        if (fp == NULL)
        {
            printf("无法写入导出文件: %s\n", path);
        }
        else
        {
            fprintf(fp, "# Algo-ID / Source\n");
            fprintf(fp, "# %s\n", ALGO_SERVERS[0].name);
            fprintf(fp, "# %s\n\n", ALGO_SERVERS[1].name);
            for (size_t i = 0; i < list.count; i++)
            {
                fprintf(fp, "%s\t%s\n", list.items[i].id,
                    server_source_label(list.items[i].server_mask));
            }
            fclose(fp);
            printf("已导出: %s\n", path);
        }
    }

    if (list.count == 0)
    {
        printf("未找到 Algo-ID, 请检查 UA 与网络\n");
    }
    else
    {
        for (size_t i = 0; i < list.count; i++)
        {
            printf("  %zu. %s [%s]\n", i + 1, list.items[i].id,
                server_source_label(list.items[i].server_mask));
        }
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
        if (prepare_ticket_batch(ua, ALGO_TICKET_BODY, ALGO_CHECKSUM, reqs, items, batch_count) == false) break;

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

bool algo_fetch_ticket_samples_from(const char* ua, const char* url, const size_t count,
    ticket_sample_t* out, size_t* out_count)
{
    ticket_request_t* reqs;
    http_post_item_t* items;
    const char* body = ALGO_ZERO_ID;
    const char* checksum = ALGO_CHECKSUM;
    size_t got = 0;

    if (ua == NULL || url == NULL || out == NULL || out_count == NULL || count == 0) return false;

    *out_count = 0;
    if (strstr(ua, "iOSdy") != NULL || strstr(ua, "macdy") != NULL)
    {
        body = "";
        checksum = "d41d8cd98f00b204e9800998ecf8427e";
    }

    reqs = calloc(count, sizeof(*reqs));
    items = calloc(count, sizeof(*items));
    if (reqs == NULL || items == NULL)
    {
        free(reqs);
        free(items);
        return false;
    }

    if (prepare_ticket_batch(ua, body, checksum, reqs, items, count) == false)
    {
        free(reqs);
        free(items);
        return false;
    }

    http_post_batch(url, items, count, TICKET_BATCH_SIZE);

    for (size_t i = 0; i < count; i++)
    {
        if (items[i].resp.curl_code == CURLE_OK && items[i].resp.http_code == 200
            && items[i].resp.body_data != NULL && items[i].resp.body_size > 0)
        {
            char id[ALGO_ID_LEN];
            if (extract_algo_id(items[i].resp.body_data, items[i].resp.body_size, id, sizeof(id)))
            {
                snprintf(out[got].algo_id, sizeof(out[got].algo_id), "%s", id);
                snprintf(out[got].client_id, sizeof(out[got].client_id), "%s", reqs[i].client_id);
                out[got].body = items[i].resp.body_data;
                out[got].body_size = items[i].resp.body_size;
                items[i].resp.body_data = NULL;
                items[i].resp.body_size = 0;
                got++;
            }
        }
        http_resp_free(&items[i].resp);
    }

    free(reqs);
    free(items);
    *out_count = got;
    return got > 0;
}

bool algo_fetch_ticket_samples(const char* ua, const size_t count, ticket_sample_t* out, size_t* out_count)
{
    return algo_fetch_ticket_samples_from(ua, ALGO_TICKET_URL, count, out, out_count);
}

bool algo_fetch_zsm_for_id(const char* ua, const char* algo_id,
    char** out_body, size_t* out_size, char* out_client_id, const size_t client_id_len)
{
    ticket_request_t req;
    http_post_item_t item;
    char algo_header[64];
    const char* body = ALGO_ZERO_ID;
    const char* checksum = ALGO_CHECKSUM;

    if (ua == NULL || algo_id == NULL || out_body == NULL || out_size == NULL) return false;
    *out_body = NULL;
    *out_size = 0;
    if (out_client_id != NULL && client_id_len > 0) out_client_id[0] = '\0';

    if (strstr(ua, "iOSdy") != NULL || strstr(ua, "macdy") != NULL)
    {
        body = "";
        checksum = "d41d8cd98f00b204e9800998ecf8427e";
    }

    memset(&req, 0, sizeof(req));
    memset(&item, 0, sizeof(item));
    if (generate_uuid(req.client_id, sizeof(req.client_id)) == false) return false;

    snprintf(req.ua_header, sizeof(req.ua_header), "User-Agent: %s", ua);
    snprintf(req.client_id_header, sizeof(req.client_id_header), "Client-ID: %s", req.client_id);
    snprintf(req.checksum_header, sizeof(req.checksum_header), "CDC-Checksum: %s", checksum);
    snprintf(algo_header, sizeof(algo_header), "Algo-ID: %s", algo_id);

    req.headers[0] = req.checksum_header;
    req.headers[1] = "Content-Type: application/x-www-form-urlencoded";
    req.headers[2] = req.ua_header;
    req.headers[3] = "Accept: " ALGO_ACCEPT;
    req.headers[4] = req.client_id_header;
    req.headers[5] = algo_header;
    req.headers[6] = "CDC-SchoolId: " CDC_SCHOOL_ID;
    req.headers[7] = "CDC-Domain: " CDC_DOMAIN;
    req.headers[8] = "CDC-Area: " CDC_AREA;
    req.headers[9] = NULL;

    item.headers = req.headers;
    item.data = body;
    http_post_batch(ALGO_TICKET_URL, &item, 1, TICKET_BATCH_SIZE);

    if (ticket_response_ok(&item.resp) == false)
    {
        http_resp_free(&item.resp);
        return false;
    }

    {
        char reported[ALGO_ID_LEN];
        if (extract_algo_id(item.resp.body_data, item.resp.body_size, reported, sizeof(reported)))
            printf("  [ZSM] 请求 Algo-ID=%s, 服务端返回=%s\n", algo_id, reported);
        else
            printf("  [ZSM] 请求 Algo-ID=%s, 服务端未返回 Algo-ID\n", algo_id);
    }

    *out_body = item.resp.body_data;
    *out_size = item.resp.body_size;
    item.resp.body_data = NULL;
    item.resp.body_size = 0;
    if (out_client_id != NULL && client_id_len > 0)
        snprintf(out_client_id, client_id_len, "%s", req.client_id);

    http_resp_free(&item.resp);
    return true;
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

#define KEY_IV_VARIANT_SUFFIX ".variants.txt"

typedef struct
{
    char id[ALGO_ID_LEN];
    char platform[16];
    int8_t type;
    char key[KEY_HEX_LEN];
    char iv[IV_HEX_LEN];
    char fingerprint[33];
    size_t variant_no;
    size_t occurrences;
} key_variant_t;

typedef struct
{
    key_variant_t* items;
    size_t count;
    size_t capacity;
} key_variant_list_t;

static void key_variant_fingerprint(const char* platform, const int8_t type,
    const char* key, const char* iv, char out[33])
{
    unsigned char digest[16];
    char data[KEY_HEX_LEN + IV_HEX_LEN + 96];

    snprintf(data, sizeof(data), "%s|%d|%s|%s",
        platform != NULL ? platform : "", type,
        key != NULL ? key : "", iv != NULL ? iv : "");
    simssl_md5((const unsigned char*)data, strlen(data), digest);
    for (int i = 0; i < 16; i++) snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[32] = '\0';
}

static int key_variant_find(const key_variant_list_t* list, const char* id,
    const char* platform, const int8_t type, const char* key, const char* iv)
{
    if (list == NULL || id == NULL) return -1;

    for (size_t i = 0; i < list->count; i++)
    {
        const key_variant_t* v = &list->items[i];
        if (strcmp(v->id, id) == 0
            && strcmp(v->platform, platform != NULL ? platform : "") == 0
            && v->type == type
            && strcmp(v->key, key != NULL ? key : "") == 0
            && strcmp(v->iv, iv != NULL ? iv : "") == 0)
        {
            return (int)i;
        }
    }
    return -1;
}

static size_t key_variant_count_id(const key_variant_list_t* list, const char* id)
{
    size_t count = 0;

    if (list == NULL || id == NULL) return 0;
    for (size_t i = 0; i < list->count; i++)
    {
        if (strcmp(list->items[i].id, id) == 0) count++;
    }
    return count;
}

static key_variant_t* key_variant_add(key_variant_list_t* list, const char* id,
    const char* platform, const int8_t type, const char* key, const char* iv)
{
    key_variant_t* item;

    if (list == NULL || id == NULL || key == NULL) return NULL;

    if (list->count == list->capacity)
    {
        const size_t new_capacity = list->capacity == 0 ? 16 : list->capacity * 2;
        key_variant_t* items = realloc(list->items, new_capacity * sizeof(*items));
        if (items == NULL) return NULL;
        list->items = items;
        list->capacity = new_capacity;
    }

    item = &list->items[list->count];
    memset(item, 0, sizeof(*item));
    snprintf(item->id, sizeof(item->id), "%s", id);
    snprintf(item->platform, sizeof(item->platform), "%s", platform != NULL ? platform : "");
    item->type = type;
    snprintf(item->key, sizeof(item->key), "%s", key);
    snprintf(item->iv, sizeof(item->iv), "%s", iv != NULL ? iv : "(none)");
    item->variant_no = key_variant_count_id(list, id) + 1;
    item->occurrences = 1;
    key_variant_fingerprint(item->platform, item->type, item->key, item->iv, item->fingerprint);
    list->count++;
    return item;
}

static const key_variant_t* key_variant_first(const key_variant_list_t* list, const char* id)
{
    if (list == NULL || id == NULL) return NULL;

    for (size_t i = 0; i < list->count; i++)
    {
        if (strcmp(list->items[i].id, id) == 0) return &list->items[i];
    }
    return NULL;
}

static void key_variant_list_free(key_variant_list_t* list)
{
    if (list == NULL) return;
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static size_t hex_value_len(const char* hex)
{
    if (hex == NULL || strcmp(hex, "(none)") == 0) return 0;
    return strlen(hex) / 2;
}

static unsigned hex_byte_at(const char* hex, const size_t index)
{
    unsigned value = 0;

    for (size_t i = 0; i < 2; i++)
    {
        const char c = hex[index * 2 + i];
        value <<= 4;
        if (c >= '0' && c <= '9') value |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') value |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') value |= (unsigned)(c - 'A' + 10);
    }
    return value;
}

static void format_hex_diff(const char* old_hex, const char* new_hex, char* out, const size_t out_len)
{
    const size_t old_len = hex_value_len(old_hex);
    const size_t new_len = hex_value_len(new_hex);
    const size_t common = old_len < new_len ? old_len : new_len;
    size_t first = SIZE_MAX;
    size_t diff_count = 0;

    for (size_t i = 0; i < common; i++)
    {
        if (hex_byte_at(old_hex, i) != hex_byte_at(new_hex, i))
        {
            if (first == SIZE_MAX) first = i;
            diff_count++;
        }
    }

    if (old_len == new_len && diff_count == 0)
    {
        snprintf(out, out_len, "相同");
    }
    else if (diff_count == 0)
    {
        snprintf(out, out_len, "长度 %zu -> %zu, 公共部分相同", old_len, new_len);
    }
    else
    {
        snprintf(out, out_len,
            "长度 %zu -> %zu, 首个差异字节 %zu (0x%02X vs 0x%02X), 共 %zu 字节不同",
            old_len, new_len, first, hex_byte_at(old_hex, first), hex_byte_at(new_hex, first), diff_count);
    }
}

static bool write_key_iv_variant(FILE* fp, const key_variant_t* base, const key_variant_t* variant)
{
    char key_diff[256];
    char iv_diff[256];

    if (fp == NULL || base == NULL || variant == NULL) return false;

    format_hex_diff(base->key, variant->key, key_diff, sizeof(key_diff));
    format_hex_diff(base->iv, variant->iv, iv_diff, sizeof(iv_diff));

    if (fprintf(fp,
            "Variant: %s#%zu\n"
            "Algo-ID: %s\n"
            "Platform: %s\n"
            "Type: %d\n"
            "Base-Platform: %s\n"
            "Base-Type: %d\n"
            "Key-Len: %zu -> %zu\n"
            "IV-Len: %zu -> %zu\n"
            "Key: %s\n"
            "IV: %s\n"
            "Compare-With: %s#%zu\n"
            "Key-Diff: %s\n"
            "IV-Diff: %s\n"
            "Fingerprint: %s\n"
            "---\n\n",
            variant->id, variant->variant_no,
            variant->id,
            variant->platform,
            (int)variant->type,
            base->platform,
            (int)base->type,
            hex_value_len(base->key), hex_value_len(variant->key),
            hex_value_len(base->iv), hex_value_len(variant->iv),
            variant->key, variant->iv,
            base->id, base->variant_no,
            key_diff, iv_diff,
            variant->fingerprint) < 0)
    {
        return false;
    }
    fflush(fp);
    return true;
}


/**
 * @brief 从已有导出文件中读取 Algo-ID 和第一份 key/iv, 用于跨次运行去重与变体比较
 */
static void load_existing_entries(const char* path, string_set_t* set,
    key_variant_list_t* variants, const bool verbose)
{
    char line[KEY_IV_LINE_LEN];
    char id[ALGO_ID_LEN] = "";
    char platform[16] = "";
    char key[KEY_HEX_LEN] = "";
    char iv[IV_HEX_LEN] = "(none)";
    int8_t type = -1;
    FILE* fp = fopen(path, "r");

    if (fp == NULL) return;

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        trim_str(line);
        if (line[0] == '#') continue;

        if (line[0] == '\0' || strncmp(line, "Index: ", 7) == 0 || strcmp(line, "---") == 0)
        {
            if (id[0] != '\0' && key[0] != '\0')
            {
                string_set_add(set, id);
                key_variant_add(variants, id, platform, type, key, iv);
            }
            id[0] = '\0';
            platform[0] = '\0';
            key[0] = '\0';
            snprintf(iv, sizeof(iv), "%s", "(none)");
            type = -1;
            if (line[0] == '\0' || strcmp(line, "---") == 0) continue;
        }

        if (strncmp(line, "Platform: ", 10) == 0)
        {
            snprintf(platform, sizeof(platform), "%.*s", (int)(sizeof(platform) - 1), line + 10);
        }
        else if (strncmp(line, "Type: ", 6) == 0)
        {
            const char* text = line + 6;
            type = (text[0] >= '0' && text[0] <= '9') ? (int8_t)atoi(text) : -1;
        }
        else if (strncmp(line, "Algo-ID: ", 9) == 0)
        {
            snprintf(id, sizeof(id), "%.*s", (int)(sizeof(id) - 1), line + 9);
        }
        else if (strncmp(line, "Key: ", 5) == 0)
        {
            snprintf(key, sizeof(key), "%.*s", (int)(sizeof(key) - 1), line + 5);
        }
        else if (strncmp(line, "IV: ", 4) == 0)
        {
            snprintf(iv, sizeof(iv), "%.*s", (int)(sizeof(iv) - 1), line + 4);
        }
    }

    if (id[0] != '\0' && key[0] != '\0')
    {
        string_set_add(set, id);
        key_variant_add(variants, id, platform, type, key, iv);
    }
    fclose(fp);

    if (verbose && set->count > 0)
    {
        printf("已从文件加载 %zu 个已有 Algo-ID, 其中 %zu 个带 key/iv 基准\n",
            set->count, variants != NULL ? variants->count : 0);
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
    else if (strstr(ua, "android") != NULL)
    {
        elf_algo_type_t type = ELF_ALGO_UNKNOWN;
        ok = get_android_zsm_key_iv(body, body_len, NULL, key, &key_len, iv, &iv_len, &type);
        cdy = (int8_t)type;
    }
    else if (strstr(ua, "Linux") != NULL)
    {
        elf_algo_type_t type = ELF_ALGO_UNKNOWN;
        ok = get_linux_zsm_key_iv(body, body_len, NULL, key, &key_len, iv, &iv_len, &type);
        cdy = (int8_t)type;
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
    if (strstr(ua, "android") != NULL) return "Android";
    if (strstr(ua, "Linux") != NULL) return "Linux";
    return "Unknown";
}

static void format_type_text(const int8_t type, char* buf, const size_t len)
{
    if (type >= 0) snprintf(buf, len, "%d", type);
    else snprintf(buf, len, "unknown");
}

static bool write_key_iv_entry(FILE* fp, const size_t index, const char* platform, const int8_t type,
    const char* id, const char* key_hex, const char* iv_hex, const char* source)
{
    char type_text[16];

    if (fp == NULL) return false;

    format_type_text(type, type_text, sizeof(type_text));
    if (fprintf(fp,
            "Index: %zu\nPlatform: %s\nType: %s\nAlgo-ID: %s\nKey: %s\nIV: %s\nSource: %s\n\n",
            index, platform, type_text, id, key_hex, iv_hex,
            source != NULL ? source : "UNKNOWN") < 0)
    {
        return false;
    }
    fflush(fp);
    return true;
}

static bool write_key_iv_source_also(FILE* fp, const char* source)
{
    if (fp == NULL) return false;
    if (fprintf(fp, "Source-Also: %s\n\n", source != NULL ? source : "UNKNOWN") < 0)
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
    size_t batch_no = 0;
    size_t total_entries = 0;
    size_t last_progress = 0;
    size_t variant_count = 0;
    string_set_t seen = {0};
    algo_id_list_t sources = {0};
    key_variant_list_t variants = {0};
    FILE* fp = NULL;
    FILE* var_fp = NULL;
    char var_path[KEY_IV_PATH_LEN + 32];
    void (*old_sigint)(int) = NULL;

    if (prompt_mode("key/iv", &mode, &count) == false) return;
    if (prompt_expected_count(&expected) == false) return;

    printf("\n请输入导出文件名 (直接回车默认 %s): ", KEY_IV_DEFAULT_FILE);
    if (read_line(path, sizeof(path)) == false) return;
    trim_str(path);
    if (path[0] == '\0') snprintf(path, sizeof(path), "%s", KEY_IV_DEFAULT_FILE);

    snprintf(var_path, sizeof(var_path), "%s%s", path, KEY_IV_VARIANT_SUFFIX);
    load_existing_entries(path, &seen, &variants, true);
    {
        const size_t before_variants = variants.count;
        load_existing_entries(var_path, &seen, &variants, false);
        if (variants.count > before_variants)
        {
            printf("已从变体文件加载 %zu 个已有变体\n", variants.count - before_variants);
        }
    }
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
        fprintf(fp, "# Index / Platform / Type / Algo-ID / Key / IV / Source\n\n");
        fflush(fp);
    }

    printf("\n开始获取 Key/IV (UA: %s)\n", ua);
    printf("服务器: %s <-> %s (交错请求)\n", ALGO_SERVERS[0].name, ALGO_SERVERS[1].name);
    if (mode == FIND_MODE_COUNT) printf("查找次数: %zu\n", count);
    else printf("一直查找, 不按次数停止 (Ctrl+C 停止)\n");

    if (strstr(ua, "WinSVR") == NULL && strstr(ua, "iOSdy") == NULL
        && strstr(ua, "macdy") == NULL && strstr(ua, "android") == NULL
        && strstr(ua, "Linux") == NULL)
    {
        printf("提示: 该 UA 没有对应的动态 ZSM 解析路径\n");
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
        if (prepare_ticket_batch(ua, ALGO_TICKET_BODY, ALGO_CHECKSUM, reqs, items, batch_count) == false) break;

        const algo_server_t* server = &ALGO_SERVERS[batch_no % ALGO_SERVER_COUNT];
        const unsigned server_mask = 1u << (batch_no % ALGO_SERVER_COUNT);
        batch_no++;

        http_post_batch(server->url, items, batch_count, TICKET_BATCH_SIZE);

        for (size_t i = 0; i < batch_count; i++)
        {
            char id[ALGO_ID_LEN];

            attempts++;

            if (ticket_response_ok(&items[i].resp))
            {
                if (extract_algo_id(items[i].resp.body_data, items[i].resp.body_size, id, sizeof(id)))
                {
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

                            const int source_add = algo_list_add(&sources, id, server_mask);
                            if (source_add == 2)
                            {
                                if (write_key_iv_source_also(fp, server->name) == false)
                                    printf("  [错误] 写入 Source-Also 失败\n");
                                printf("  [同ID新服务器] %s [%s]\n", id, server->name);
                            }

                            if (string_set_contains(&seen, id) == false)
                            {
                                if (write_key_iv_entry(fp, total_entries + 1, platform, cdy, id,
                                        key_hex, iv_hex, server->name) == false)
                                {
                                    printf("  [错误] 写入文件失败: %s\n", path);
                                }
                                else
                                {
                                    string_set_add(&seen, id);
                                    key_variant_add(&variants, id, platform, cdy, key_hex, iv_hex);
                                    exported++;
                                    total_entries++;
                                    printf("  [新] #%zu %s [%s]\n       Platform: %s\n       Type: %s\n       Key: %s\n       IV: %s\n",
                                        total_entries, id, server->name, platform, type_text, key_hex, iv_hex);
                                }
                            }
                            else
                            {
                                const int found = key_variant_find(&variants, id, platform, cdy, key_hex, iv_hex);
                                if (found >= 0)
                                {
                                    variants.items[found].occurrences++;
                                }
                                else
                                {
                                    key_variant_t* added = key_variant_add(&variants, id, platform, cdy, key_hex, iv_hex);
                                    const key_variant_t* base = key_variant_first(&variants, id);

                                    if (added != NULL && base != NULL && added != base)
                                    {
                                        if (var_fp == NULL)
                                        {
                                            var_fp = fopen(var_path, "a");
                                            if (var_fp != NULL)
                                            {
                                                fseek(var_fp, 0, SEEK_END);
                                                if (ftell(var_fp) == 0)
                                                {
                                                    fprintf(var_fp,
                                                        "# Algo-ID Key/IV variants\n"
                                                        "# Fingerprint = MD5(Platform|Type|Key|IV)\n"
                                                        "# Compare-With = 同 Algo-ID 的基准变体\n\n");
                                                    fflush(var_fp);
                                                }
                                            }
                                            else
                                            {
                                                printf("  [错误] 无法打开变体文件: %s\n", var_path);
                                            }
                                        }

                                        if (var_fp != NULL && write_key_iv_variant(var_fp, base, added))
                                        {
                                            char base_type_text[16];
                                            format_type_text(base->type, base_type_text, sizeof(base_type_text));
                                            variant_count++;
                                            printf("  [变体] %s #%zu (基准 #%zu)\n"
                                                   "         Type: %s -> %s, Key-Len: %zu -> %zu, IV-Len: %zu -> %zu\n"
                                                   "         Key: %s\n"
                                                   "         IV: %s\n"
                                                   "         Fingerprint: %s\n",
                                                id, added->variant_no, base->variant_no,
                                                base_type_text, type_text,
                                                hex_value_len(base->key), hex_value_len(added->key),
                                                hex_value_len(base->iv), hex_value_len(added->iv),
                                                key_hex, iv_hex, added->fingerprint);
                                        }
                                    }
                                }
                            }
                        }
                        else if (is_fixed_algo_id(id) && string_set_contains(&seen, id) == false)
                        {
                            string_set_add(&seen, id);
                            printf("  [跳过] %s (固定算法, key/iv 在代码中)\n", id);
                        }
                        else if (string_set_contains(&seen, id) == false)
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
    if (var_fp != NULL) fclose(var_fp);
    printf("\n获取结束: 共查找 %zu 次, 导出 %zu 条, 文件: %s\n", attempts, exported, path);
    if (variant_count > 0) printf("发现 %zu 个 key/iv 变体, 文件: %s\n", variant_count, var_path);
    else printf("未发现同 Algo-ID 的 key/iv 变体\n");
    key_variant_list_free(&variants);
    string_set_free(&seen);
    algo_list_free(&sources);
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
