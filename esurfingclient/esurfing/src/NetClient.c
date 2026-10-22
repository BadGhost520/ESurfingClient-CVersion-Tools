#include "NetClient.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HTTP_CONNECT_TIMEOUT 1L
#define HTTP_MAX_REDIRS 5L
#define HTTP_BATCH_TIMEOUT 1L
#define HTTP_DEFAULT_CONCURRENCY 8

typedef struct
{
    http_post_item_t* item;
    CURL* easy;
    struct curl_slist* headers;
    bool done;
} http_batch_slot_t;

static size_t write_cb(const void* contents, const size_t size, const size_t nmemb, void* userdata)
{
    http_resp_t* resp = userdata;
    const size_t real_size = size * nmemb;
    char* ptr = realloc(resp->body_data, resp->body_size + real_size + 1);

    if (ptr == NULL) return 0;

    resp->body_data = ptr;
    memcpy(resp->body_data + resp->body_size, contents, real_size);
    resp->body_size += real_size;
    resp->body_data[resp->body_size] = '\0';
    return real_size;
}

static void resp_set_error(http_resp_t* resp, const CURLcode code, const char* msg)
{
    resp->curl_code = code;
    snprintf(resp->error, sizeof(resp->error), "%s", msg != NULL ? msg : curl_easy_strerror(code));
}

static bool header_name_is(const char* header, const char* name)
{
    while (*name != '\0')
    {
        if (tolower((unsigned char)*header) != tolower((unsigned char)*name)) return false;
        header++;
        name++;
    }
    return *header == ':';
}

static void header_copy_value(const char* header, const size_t name_len, char* out, const size_t out_len)
{
    const char* value = header + name_len + 1;
    size_t value_len;

    if (out == NULL || out_len == 0) return;
    while (*value == ' ' || *value == '\t') value++;
    value_len = strcspn(value, "\r\n");
    while (value_len > 0 && (value[value_len - 1] == ' ' || value[value_len - 1] == '\t')) value_len--;
    if (value_len >= out_len) value_len = out_len - 1;
    memcpy(out, value, value_len);
    out[value_len] = '\0';
}

static size_t header_cb(const void* contents, const size_t size, const size_t nmemb, void* userdata)
{
    const size_t real_size = size * nmemb;
    const char* header = contents;
    http_resp_t* resp = userdata;

    if (resp != NULL && real_size > 2)
    {
        if (resp->error_code[0] == '\0' && header_name_is(header, "error-code"))
        {
            header_copy_value(header, strlen("error-code"), resp->error_code, sizeof(resp->error_code));
        }
        else if (resp->sub_error[0] == '\0' && header_name_is(header, "sub-error"))
        {
            header_copy_value(header, strlen("sub-error"), resp->sub_error, sizeof(resp->sub_error));
        }
    }
    return real_size;
}

bool http_global_init()
{
    return curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
}

void http_global_cleanup()
{
    curl_global_cleanup();
}

/**
 * @brief 初始化一个 easy handle 并加入 multi
 * @return 是否成功
 */
static bool batch_start_slot(CURLM* multi, const char* url, http_batch_slot_t* slot, const long timeout)
{
    http_post_item_t* item = slot->item;
    struct curl_slist* header_list = NULL;
    CURL* easy;

    if (item->data == NULL)
    {
        resp_set_error(&item->resp, CURLE_BAD_FUNCTION_ARGUMENT, "POST 数据为空");
        return false;
    }

    easy = curl_easy_init();
    if (easy == NULL)
    {
        resp_set_error(&item->resp, CURLE_FAILED_INIT, "curl 初始化失败");
        return false;
    }

    if (item->headers != NULL)
    {
        for (size_t i = 0; item->headers[i] != NULL; i++)
        {
            struct curl_slist* next = curl_slist_append(header_list, item->headers[i]);
            if (next == NULL)
            {
                curl_slist_free_all(header_list);
                curl_easy_cleanup(easy);
                resp_set_error(&item->resp, CURLE_OUT_OF_MEMORY, "添加请求头失败");
                return false;
            }
            header_list = next;
        }
    }

    curl_easy_setopt(easy, CURLOPT_URL, url);
    curl_easy_setopt(easy, CURLOPT_POST, 1L);
    curl_easy_setopt(easy, CURLOPT_POSTFIELDS, item->data);
    curl_easy_setopt(easy, CURLOPT_HTTPHEADER, header_list);
    curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(easy, CURLOPT_MAXREDIRS, HTTP_MAX_REDIRS);
    curl_easy_setopt(easy, CURLOPT_POSTREDIR, CURL_REDIR_POST_ALL);
    curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT, HTTP_CONNECT_TIMEOUT);
    curl_easy_setopt(easy, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(easy, CURLOPT_ERRORBUFFER, item->resp.error);
    curl_easy_setopt(easy, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(easy, CURLOPT_HEADERDATA, &item->resp);
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(easy, CURLOPT_WRITEDATA, &item->resp);
    curl_easy_setopt(easy, CURLOPT_PRIVATE, slot);

    const CURLMcode mc = curl_multi_add_handle(multi, easy);
    if (mc != CURLM_OK)
    {
        resp_set_error(&item->resp, CURLE_FAILED_INIT, curl_multi_strerror(mc));
        curl_easy_cleanup(easy);
        curl_slist_free_all(header_list);
        return false;
    }

    slot->easy = easy;
    slot->headers = header_list;
    return true;
}

void http_post_batch_timeout(const char* url, http_post_item_t* items, const size_t count,
    const size_t max_concurrent, const long timeout)
{
    http_batch_slot_t* slots;
    CURLM* multi;
    size_t limit;
    size_t next = 0;
    size_t active = 0;
    size_t completed = 0;
    int still_running = 0;

    if (items == NULL || count == 0) return;

    for (size_t i = 0; i < count; i++) memset(&items[i].resp, 0, sizeof(items[i].resp));

    if (url == NULL)
    {
        for (size_t i = 0; i < count; i++) resp_set_error(&items[i].resp, CURLE_BAD_FUNCTION_ARGUMENT, "URL 为空");
        return;
    }

    slots = calloc(count, sizeof(*slots));
    if (slots == NULL)
    {
        for (size_t i = 0; i < count; i++) resp_set_error(&items[i].resp, CURLE_OUT_OF_MEMORY, "分配请求槽失败");
        return;
    }

    multi = curl_multi_init();
    if (multi == NULL)
    {
        free(slots);
        for (size_t i = 0; i < count; i++) resp_set_error(&items[i].resp, CURLE_FAILED_INIT, "curl multi 初始化失败");
        return;
    }

    limit = max_concurrent > 0 ? max_concurrent : HTTP_DEFAULT_CONCURRENCY;
    if (limit > count) limit = count;

    while (next < count && active < limit)
    {
        slots[next].item = &items[next];
        if (batch_start_slot(multi, url, &slots[next], timeout)) active++;
        else
        {
            slots[next].done = true;
            completed++;
        }
        next++;
    }

    while (completed < count)
    {
        const CURLMcode mc = curl_multi_perform(multi, &still_running);
        if (mc != CURLM_OK)
        {
            for (size_t i = 0; i < count; i++)
            {
                if (slots[i].done) continue;
                resp_set_error(&items[i].resp, CURLE_FAILED_INIT, curl_multi_strerror(mc));
                slots[i].done = true;
                completed++;
            }
            break;
        }

        int queued = 0;
        CURLMsg* msg;
        while ((msg = curl_multi_info_read(multi, &queued)) != NULL)
        {
            if (msg->msg != CURLMSG_DONE) continue;

            CURL* easy = msg->easy_handle;
            char* private_ptr = NULL;
            http_batch_slot_t* slot;

            curl_easy_getinfo(easy, CURLINFO_PRIVATE, &private_ptr);
            slot = (http_batch_slot_t*)private_ptr;
            if (slot == NULL)
            {
                curl_multi_remove_handle(multi, easy);
                curl_easy_cleanup(easy);
                continue;
            }

            slot->item->resp.curl_code = msg->data.result;
            if (msg->data.result == CURLE_OK)
            {
                curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &slot->item->resp.http_code);
            }
            else if (slot->item->resp.error[0] == '\0')
            {
                snprintf(slot->item->resp.error, sizeof(slot->item->resp.error), "%s",
                    curl_easy_strerror(msg->data.result));
            }

            curl_multi_remove_handle(multi, easy);
            curl_easy_cleanup(easy);
            curl_slist_free_all(slot->headers);
            slot->easy = NULL;
            slot->headers = NULL;
            slot->done = true;
            completed++;
            if (active > 0) active--;

            while (next < count && active < limit)
            {
                slots[next].item = &items[next];
                if (batch_start_slot(multi, url, &slots[next], HTTP_BATCH_TIMEOUT)) active++;
                else
                {
                    slots[next].done = true;
                    completed++;
                }
                next++;
            }
        }

        if (completed >= count) break;

        if (active == 0 && next >= count)
        {
            for (size_t i = 0; i < count; i++)
            {
                if (slots[i].done) continue;
                resp_set_error(&items[i].resp, CURLE_FAILED_INIT, "请求未完成");
                slots[i].done = true;
                completed++;
            }
            break;
        }

        if (still_running > 0)
        {
            int numfds = 0;
            curl_multi_wait(multi, NULL, 0, 1000, &numfds);
        }
    }

    for (size_t i = 0; i < count; i++)
    {
        if (slots[i].done) continue;

        if (slots[i].easy != NULL)
        {
            curl_multi_remove_handle(multi, slots[i].easy);
            curl_easy_cleanup(slots[i].easy);
        }
        curl_slist_free_all(slots[i].headers);
        if (items[i].resp.curl_code == CURLE_OK) resp_set_error(&items[i].resp, CURLE_FAILED_INIT, "请求未完成");
    }

    curl_multi_cleanup(multi);
    free(slots);
}

void http_post_batch(const char* url, http_post_item_t* items, const size_t count, const size_t max_concurrent)
{
    http_post_batch_timeout(url, items, count, max_concurrent, HTTP_BATCH_TIMEOUT);
}

http_resp_t http_post(const char* url, const char* const* headers, const char* data)
{
    http_post_item_t item;

    item.headers = headers;
    item.data = data;
    memset(&item.resp, 0, sizeof(item.resp));

    http_post_batch(url, &item, 1, 1);
    return item.resp;
}

http_resp_t http_post_timeout(const char* url, const char* const* headers, const char* data, const long timeout)
{
    http_post_item_t item;

    item.headers = headers;
    item.data = data;
    memset(&item.resp, 0, sizeof(item.resp));

    http_post_batch_timeout(url, &item, 1, 1, timeout);
    return item.resp;
}

void http_resp_free(http_resp_t* resp)
{
    if (resp == NULL) return;

    free(resp->body_data);
    resp->body_data = NULL;
    resp->body_size = 0;
    resp->http_code = 0;
    resp->curl_code = CURLE_OK;
    resp->error[0] = '\0';
    resp->error_code[0] = '\0';
    resp->sub_error[0] = '\0';
}
