#include "TicketCheck.h"

#include "AlgoFinder.h"
#include "NetClient.h"
#include "cipher/CipherInterface.h"
#include "utils/Utils.h"
#include "utils/sim/SimEvp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#define TICKET_REQUEST_RETRY 3
#define TICKET_REQUEST_DELAY_MS 300

#define TICKET_XML_LEN 1024
#define TICKET_ACCEPT "text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*"
#define TICKET_SCHOOL_ID "221"
#define TICKET_DOMAIN "zsdzkd"
#define TICKET_AREA "0760"
#define MAX_GROUP_IDS 64
#define SAMPLE_BATCH_SIZE 24
#define NO_NEW_SAMPLE_LIMIT 1000

static const char* const WINDOWS_IDS[] = {
    "03F8A638-5C23-418B-972C-A2BA6927EF77",
    "054DDD03-911E-49F5-89D6-EFBF5055FBFF",
    "066474E5-503E-4B82-98C4-DF4483DAF0B5",
    "079637D7-A2A2-41CE-A50D-4CAD3B2334E7",
    "083B005A-7ACA-419A-AC00-6929C0AADB55",
    "08BDB042-5D25-4397-875F-357E9F7700C8",
    "0A2375CB-1F91-4064-B00F-1CF3A1AF6E4A",
    "11734889-14D8-48FA-ACEC-36452CA3FE8D",
    "1401F41B-06EA-4236-8E68-7AA1555A7C28",
    "1B652785-1153-4741-8A1C-2D9E752BE0E5",
    "2C2C4070-6644-4E84-BDBD-1760A2DA875C",
    "37620C35-7A97-4A4F-9EF3-822DD38FE211",
    "376412D4-ACA3-4452-8A79-4589B3817760",
    "42184E84-A844-486E-83C3-4CB9FD874D67",
    "466FBBBF-E526-4A13-A306-6AF402688F5E",
    "46D3C896-2B45-41B2-91B6-A5C9718EF7CD",
    "47C78640-9E7D-4115-B140-BE2DF6C49BF9",
    "50495282-EDFD-4371-B4FE-6706326B2F12",
    "52271930-386B-4EC7-B5E9-7DEF7C1C11A8",
    "5678F2AA-C270-4F0A-9CB3-AE7A5D912FCD",
    "578FDB96-AF47-461D-AC36-D08EADF10130",
    "6067E3B6-3AB5-45AE-8CEC-E8DACB3C76DE",
    "68361562-0864-4EB3-8508-9CDE34269D8C",
    "70CDBBAB-C9C9-49DE-A8D9-068579EAFFD0",
    "76CD0763-8C5F-49B0-85CD-549BB32886A2",
    "7809936E-EA7E-4BA2-AD3B-5621259530FC",
    "78AD4214-E71F-421A-A13B-C65EC32890C3",
    "79F1CC4F-A213-4DE0-AAED-A276D2E1F21F",
    "7DE2123D-3868-4D5E-86A1-687FE2683476",
    "7EDCC3AB-5B1B-409A-A5E3-E9623A5EC1B7",
    "895E36A7-0175-4EF2-A00D-7F3482D70D72",
    "9E6620CB-628D-49CA-80DD-9E6BCA401A31",
    "ABA03E9C-E7E3-4AD0-94F9-4224DAA975C4",
    "AF69A651-96D0-4B88-B388-644CB6822159",
    "B453C03E-871D-4B13-8AD1-EB61162F2EED",
    "BFAC1582-AA39-4CBC-AD0E-6D37ACDA369B",
    "CA582532-4E58-448A-976B-4E1E9809966B",
    "CAC870CA-C03D-475A-8CB0-F4E9C80B9153",
    "CF750526-3D99-44BE-A0DE-09DEADC97D52",
    "DDE9BF30-FBD3-4184-9B38-8855C1F47FD1",
    "E2BC8BAC-D7E0-4DAD-9400-789C63D6A0DC",
    "E9747EF1-6849-4F87-957B-3B93E6A90393",
    "EB353E96-94B2-486C-9FA6-31A37C222EA7",
    "EBD34028-0E59-4B21-86EB-CF892E75F6FF",
    "ECE4A1E8-A530-48B2-B968-F503CB1CBAAC",
    "EE0D4296-FC76-4BBB-8E0D-B03DB50776F2",
    "F1C01068-FFAB-4E4E-A043-0B06B2299AF4",
    "F6B5CFB0-17FD-453C-9791-B2887E2C9859",
    "FC05D786-59A7-4469-B276-0D9B89EAD057",
    "FEE5E4DA-50A0-4ECD-8392-92E09CB1B775",
};

static const char* const IOS_IDS[] = {
    "2E75BFA5-76C5-4691-BBF5-A49C94908464",
    "4D10D93E-5A68-46D4-83EA-49E7C4933C91",
    "E2F8C4B2-2742-4690-9BD5-BBAB926FB9E8",
};

static const char* const MACOS_IDS[] = {
    "634D7C6F-581F-47CC-959C-D9265EDAB9B4",
    "7781847B-446E-4CF7-A418-79989EFA1B00",
    "E366503B-B6E5-40A5-BCE1-39001D18D90E",
};

static const char* const ANDROID_OLD_IDS[] = {
    "CAFBCBAD-B6E7-4CAB-8A67-14D39F00CE1E",
    "A474B1C2-3DE0-4EA2-8C5F-7093409CE6C4",
    "5BFBA864-BBA9-42DB-8EAD-49B5F412BD81",
    "6E0B65FF-0B5B-459C-8FCE-EC7F2BEA9FF5",
    "B809531F-0007-4B5B-923B-4BD560398113",
    "F3974434-C0DD-4C20-9E87-DDB6814A1C48",
    "ED382482-F72C-4C41-A76D-28EEA0F1F2AF",
    "B3047D4E-67DF-4864-A6A5-DF9B9E525C79",
    "C32C68F9-CA81-4260-A329-BBAFD1A9CCD1",
};

static const char* const ANDROID_NEW_IDS[] = {
    "07E824B2-9E5C-4D1B-BBB0-5E07C251E4AA",
    "319FC5AB-EC0E-46B9-A252-2285F9DAE813",
    "D6544CFE-F2DE-459B-9B77-0F2B367EF169",
    "D755A536-B551-468C-BD87-322182B223D4",
    "BB2EA626-590B-4C42-82BE-E052FCBBB88E",
    "DEABB8C8-A2BC-48CA-8ED0-8CDF1BD62F61",
    "9ABF4D29-34DB-4CE9-BB8C-7E371D637758",
    "AD8BB5B0-0E72-4198-A362-96D52C1B7ED1",
    "35101415-A20F-4DFE-B00B-0B4F3B2F8C66",
};

static const char* const LINUX_IDS[] = {
    "1A7343EC-7F9B-4570-BF58-16279A81116B",
    "4BA5496A-2123-46A7-85F2-35956EA7BE39",
    "45433DCF-9ECA-4BE5-83F2-F92BA0B4F291",
    "60639D8B-272E-4A4D-976E-AA270987A169",
    "AB6C8EBE-B8F8-4C08-8222-69A3B5E86A91",
    "B306E770-B7D5-49F2-A574-BCE2C5C650ED",
};

typedef struct
{
    const char* name;
    const char* file_tag;
    const char* const* ids;
    size_t count;
} ticket_group_t;

#define GROUP_ENTRY(name, tag, ids) { name, tag, ids, sizeof(ids) / sizeof(ids[0]) }

static const ticket_group_t s_groups[] = {
    GROUP_ENTRY("Windows", "windows", WINDOWS_IDS),
    GROUP_ENTRY("iOS", "ios", IOS_IDS),
    GROUP_ENTRY("macOS", "macos", MACOS_IDS),
    GROUP_ENTRY("Android 旧版", "android_old", ANDROID_OLD_IDS),
    GROUP_ENTRY("Android 新版", "android_new", ANDROID_NEW_IDS),
    GROUP_ENTRY("Linux", "linux", LINUX_IDS),
};

static void sleep_ms(const unsigned ms)
{
#ifdef _WIN32
    Sleep(ms);
#else
    usleep(ms * 1000);
#endif
}

static void url_param(const char* url, const char* key, char* out, const size_t out_len)
{
    const size_t key_len = strlen(key);
    const char* p = url;

    if (out == NULL || out_len == 0) return;
    out[0] = '\0';
    if (url == NULL || key == NULL) return;

    while ((p = strstr(p, key)) != NULL)
    {
        const bool at_boundary = (p == url) || p[-1] == '?' || p[-1] == '&';
        if (at_boundary && p[key_len] == '=')
        {
            const char* value = p + key_len + 1;
            size_t len = 0;
            while (value[len] != '\0' && value[len] != '&' && value[len] != '#') len++;
            if (len >= out_len) len = out_len - 1;
            memcpy(out, value, len);
            out[len] = '\0';
            return;
        }
        p += key_len;
    }
}

static void uuid_to_hex(const char* uuid, char* hex, const size_t hex_len)
{
    size_t j = 0;

    if (hex == NULL || hex_len == 0) return;
    for (size_t i = 0; uuid != NULL && uuid[i] != '\0' && j + 1 < hex_len; i++)
    {
        if (uuid[i] != '-') hex[j++] = uuid[i];
    }
    hex[j] = '\0';
}

static void md5_hex(const char* data, char out[33])
{
    unsigned char digest[16];

    simssl_md5((const unsigned char*)data, strlen(data), digest);
    for (int i = 0; i < 16; i++) snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[32] = '\0';
}

static char* extract_tag(const char* xml, const char* tag)
{
    char start[64];
    char end[64];
    const char* p;
    const char* q;
    size_t len;
    char* value;

    if (xml == NULL || tag == NULL) return NULL;
    snprintf(start, sizeof(start), "<%s>", tag);
    snprintf(end, sizeof(end), "</%s>", tag);
    p = strstr(xml, start);
    if (p == NULL) return NULL;
    p += strlen(start);
    q = strstr(p, end);
    if (q == NULL || q <= p) return NULL;

    len = (size_t)(q - p);
    value = malloc(len + 1);
    if (value == NULL) return NULL;
    memcpy(value, p, len);
    value[len] = '\0';
    return value;
}

static bool fill_identity(const char* url, char* host_name, const size_t host_name_len,
    char* ostag, const size_t ostag_len, char* mac, const size_t mac_len,
    char* client_ip, const size_t client_ip_len, char* ac_ip, const size_t ac_ip_len,
    char* local_time, const size_t local_time_len)
{
    char identity[37];
    char identity_hex[33];
    time_t now;
    struct tm local_tm;

    if (generate_uuid(identity, sizeof(identity)) == false) return false;
    uuid_to_hex(identity, identity_hex, sizeof(identity_hex));

    snprintf(host_name, host_name_len, "%.10s", identity_hex);
    snprintf(ostag, ostag_len, "%.10s", identity_hex);
    snprintf(mac, mac_len, "02:%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
        identity_hex[10], identity_hex[11], identity_hex[12], identity_hex[13],
        identity_hex[14], identity_hex[15], identity_hex[16], identity_hex[17],
        identity_hex[18], identity_hex[19], identity_hex[20], identity_hex[21]);

    url_param(url, "wlanuserip", client_ip, client_ip_len);
    url_param(url, "wlanacip", ac_ip, ac_ip_len);

    now = time(NULL);
#ifdef _WIN32
    if (localtime_s(&local_tm, &now) != 0) return false;
#else
    if (localtime_r(&now, &local_tm) == NULL) return false;
#endif
    return strftime(local_time, local_time_len, "%Y-%m-%d %H:%M:%S", &local_tm) > 0;
}

static bool check_one_id(const char* ua, const char* url, const char* algo_id,
    const char* client_id, const char* zsm, const size_t zsm_len,
    char* reason, const size_t reason_len)
{
    char host_name[16];
    char ostag[16];
    char mac[24];
    char client_ip[64];
    char ac_ip[64];
    char local_time[32];
    char xml[TICKET_XML_LEN];
    char checksum[33];
    char checksum_header[64];
    char ua_header[ALGO_UA_LEN + 16];
    char client_header[80];
    char algo_header[64];
    char last_error[160] = "";
    const char* headers[10];
    char* encrypted = NULL;
    char* plain = NULL;
    char* ticket = NULL;
    http_resp_t resp;
    bool inited = false;
    bool request_ok = false;
    bool ok = false;

    if (reason != NULL && reason_len > 0) reason[0] = '\0';

    if (fill_identity(url, host_name, sizeof(host_name), ostag, sizeof(ostag),
            mac, sizeof(mac), client_ip, sizeof(client_ip), ac_ip, sizeof(ac_ip),
            local_time, sizeof(local_time)) == false)
    {
        snprintf(reason, reason_len, "生成身份字段失败");
        return false;
    }

    if (init_cipher(algo_id))
    {
        inited = true;
    }
    else if (strstr(ua, "WinSVR") != NULL)
    {
        inited = init_win_cipher_from_zsm((const uint8_t*)zsm, zsm_len, NULL);
    }
    else if (strstr(ua, "iOSdy") != NULL || strstr(ua, "macdy") != NULL)
    {
        inited = init_ios_cipher_from_zsm((const uint8_t*)zsm, zsm_len, NULL);
    }

    if (inited == false)
    {
        snprintf(reason, reason_len, "初始化算法失败");
        return false;
    }

    snprintf(xml, sizeof(xml),
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<request>\n"
        "    <user-agent>%s</user-agent>\n"
        "    <client-id>%s</client-id>\n"
        "    <local-time>%s</local-time>\n"
        "    <host-name>%s</host-name>\n"
        "    <ipv4>%s</ipv4>\n"
        "    <ipv6></ipv6>\n"
        "    <mac>%s</mac>\n"
        "    <ostag>%s</ostag>\n"
        "    <gwip>%s</gwip>\n"
        "</request>\n",
        ua, client_id, local_time, host_name, client_ip, mac, ostag, ac_ip);

    encrypted = session_encrypt(xml);
    if (encrypted == NULL)
    {
        snprintf(reason, reason_len, "加密失败");
        goto cleanup;
    }

    md5_hex(encrypted, checksum);
    snprintf(checksum_header, sizeof(checksum_header), "CDC-Checksum: %s", checksum);
    snprintf(ua_header, sizeof(ua_header), "User-Agent: %s", ua);
    snprintf(client_header, sizeof(client_header), "Client-ID: %s", client_id);
    snprintf(algo_header, sizeof(algo_header), "Algo-ID: %s", algo_id);

    headers[0] = checksum_header;
    headers[1] = "Content-Type: application/x-www-form-urlencoded";
    headers[2] = ua_header;
    headers[3] = "Accept: " TICKET_ACCEPT;
    headers[4] = client_header;
    headers[5] = algo_header;
    headers[6] = "CDC-SchoolId: " TICKET_SCHOOL_ID;
    headers[7] = "CDC-Domain: " TICKET_DOMAIN;
    headers[8] = "CDC-Area: " TICKET_AREA;
    headers[9] = NULL;

    sleep_ms(150);
    for (int attempt = 0; attempt < TICKET_REQUEST_RETRY; attempt++)
    {
        resp = http_post_timeout(url, headers, encrypted, 5L);
        if (resp.curl_code == CURLE_OK && resp.http_code == 200
            && resp.body_data != NULL && resp.body_size > 0)
        {
            request_ok = true;
            break;
        }

        const bool explicit_error = resp.error_code[0] != '\0';
        if (explicit_error)
        {
            snprintf(last_error, sizeof(last_error), "Error-Code=%s%s%s",
                resp.error_code,
                resp.sub_error[0] != '\0' ? " / Sub-Error=" : "",
                resp.sub_error[0] != '\0' ? resp.sub_error : "");
        }
        else if (resp.curl_code == CURLE_OPERATION_TIMEDOUT)
        {
            snprintf(last_error, sizeof(last_error), "请求超时");
        }
        else if (resp.http_code != 200)
        {
            snprintf(last_error, sizeof(last_error), "HTTP %ld", resp.http_code);
        }
        else
        {
            snprintf(last_error, sizeof(last_error), "响应为空");
        }

        http_resp_free(&resp);
        if (explicit_error) break;
        if (attempt + 1 < TICKET_REQUEST_RETRY) sleep_ms(TICKET_REQUEST_DELAY_MS);
    }
    if (request_ok == false)
    {
        snprintf(reason, reason_len, "%s", last_error[0] != '\0' ? last_error : "Ticket 请求失败");
        goto cleanup;
    }

    plain = session_decrypt(resp.body_data);
    http_resp_free(&resp);
    if (plain == NULL)
    {
        snprintf(reason, reason_len, "响应解密失败");
        goto cleanup;
    }

    ticket = extract_tag(plain, "ticket");
    if (ticket == NULL || ticket[0] == '\0')
    {
        snprintf(reason, reason_len, "响应中没有 ticket");
        goto cleanup;
    }

    ok = true;

cleanup:
    free(ticket);
    free(plain);
    free(encrypted);
    destroy_cipher_factory();
    return ok;
}

static const ticket_group_t* select_group(const char* ua)
{
    if (strstr(ua, "WinSVR") != NULL) return &s_groups[0];
    if (strstr(ua, "iOSdy") != NULL) return &s_groups[1];
    if (strstr(ua, "macdy") != NULL) return &s_groups[2];
    if (strstr(ua, "android64_vpn") != NULL) return &s_groups[3];
    if (strstr(ua, "android") != NULL) return &s_groups[4];
    if (strstr(ua, "Linux") != NULL) return &s_groups[5];
    return NULL;
}

static int find_id(const ticket_group_t* group, const char* algo_id)
{
    for (size_t i = 0; i < group->count; i++)
    {
        if (strcmp(group->ids[i], algo_id) == 0) return (int)i;
    }
    return -1;
}

void ticket_check_run(void)
{
    char ua[ALGO_UA_LEN];
    bool tested[MAX_GROUP_IDS] = {false};
    const char* failed[MAX_GROUP_IDS];
    size_t failed_count = 0;
    size_t tested_count = 0;
    size_t success_count = 0;
    size_t samples = 0;
    size_t no_new = 0;
    size_t empty_batches = 0;
    const ticket_group_t* group;
    const char* url;

    if (algo_prompt_ua(ua, sizeof(ua)) == false) return;

    group = select_group(ua);
    if (group == NULL)
    {
        printf("无法根据 UA 判断平台, 支持 Windows/iOS/macOS/Android/Linux\n");
        return;
    }

    url = algo_ticket_url();
    {
        char old_path[64];
        snprintf(old_path, sizeof(old_path), "ticket_failed_%s.txt", group->file_tag);
        remove(old_path);
    }
    printf("\n开始检查 %s 的 %zu 个硬编码 Algo-ID\n", group->name, group->count);
    printf("Ticket URL: %s\n\n", url);

    while (tested_count < group->count && no_new < NO_NEW_SAMPLE_LIMIT)
    {
        ticket_sample_t batch[SAMPLE_BATCH_SIZE];
        size_t got = 0;

        if (algo_fetch_ticket_samples(ua, SAMPLE_BATCH_SIZE, batch, &got) == false)
        {
            empty_batches++;
            if (empty_batches >= 3)
            {
                printf("  连续 3 批采样失败, 结束检查\n");
                break;
            }
            continue;
        }
        empty_batches = 0;

        for (size_t i = 0; i < got; i++)
        {
            const int idx = find_id(group, batch[i].algo_id);
            samples++;

            if (idx < 0 || tested[idx])
            {
                no_new++;
            }
            else
            {
                char reason[192] = "";

                tested[idx] = true;
                tested_count++;
                no_new = 0;
                printf("  [%zu/%zu] %s ... ", tested_count, group->count, group->ids[idx]);
                fflush(stdout);

                if (check_one_id(ua, url, group->ids[idx], batch[i].client_id,
                        batch[i].body, batch[i].body_size, reason, sizeof(reason)))
                {
                    printf("OK\n");
                    success_count++;
                }
                else
                {
                    printf("FAIL (%s)\n", reason[0] != '\0' ? reason : "未知错误");
                    if (failed_count < MAX_GROUP_IDS) failed[failed_count++] = group->ids[idx];
                }
            }

            free(batch[i].body);
        }

        if (samples / 100 != (samples - got) / 100)
        {
            printf("  ... 已采样 %zu 次, 已检查 %zu/%zu\n", samples, tested_count, group->count);
        }
    }

    for (size_t i = 0; i < group->count; i++)
    {
        if (!tested[i] && failed_count < MAX_GROUP_IDS)
        {
            failed[failed_count++] = group->ids[i];
        }
    }

    printf("\n检查完成: 共 %zu 个, 成功 %zu 个, 失败 %zu 个, 采样 %zu 次\n",
        group->count, success_count, failed_count, samples);

    if (failed_count == 0)
    {
        printf("全部 Algo-ID 都能正常获取 Ticket\n");
        return;
    }

    {
        char path[64];
        snprintf(path, sizeof(path), "ticket_failed_%s.txt", group->file_tag);
        FILE* fp = fopen(path, "w");
        if (fp == NULL)
        {
            printf("无法写入失败列表: %s\n", path);
            return;
        }
        fprintf(fp, "# UA: %s\n# Ticket 获取失败的 Algo-ID\n\n", ua);
        for (size_t i = 0; i < failed_count; i++) fprintf(fp, "%s\n", failed[i]);
        fclose(fp);
        printf("失败 Algo-ID 已写入: %s\n", path);
    }
}
