#ifndef ESURFINGCLIENT_NETCLIENT_H
#define ESURFINGCLIENT_NETCLIENT_H

#include <curl/curl.h>

#include <stdbool.h>
#include <stddef.h>

/** @brief HTTP 响应 */
typedef struct
{
    /** @brief curl 错误码 */
    CURLcode curl_code;
    /** @brief HTTP 状态码 */
    long http_code;
    /** @brief 响应体 */
    char* body_data;
    /** @brief 响应体长度 */
    size_t body_size;
    /** @brief curl 错误信息 */
    char error[CURL_ERROR_SIZE];
} http_resp_t;

/**
 * @brief 初始化 curl 全局环境
 * @return 是否初始化成功
 */
bool http_global_init();

/**
 * @brief 清理 curl 全局环境
 */
void http_global_cleanup();

/**
 * @brief 发送带自定义请求头的 POST 请求
 * @param url 地址
 * @param headers 请求头数组, 以 NULL 结尾
 * @param data POST 数据
 * @return 响应数据
 */
http_resp_t http_post(const char* url, const char* const* headers, const char* data);

/** @brief 单个 POST 请求参数与响应 */
typedef struct
{
    /** @brief 请求头数组, 以 NULL 结尾 */
    const char* const* headers;
    /** @brief POST 数据 */
    const char* data;
    /** @brief 响应数据 */
    http_resp_t resp;
} http_post_item_t;

/**
 * @brief 并发执行多个 POST 请求
 * @param url 地址
 * @param items 请求数组, 响应写回 items[i].resp
 * @param count 请求数量
 * @param max_concurrent 最大并发数, 0 使用默认值
 */
void http_post_batch(const char* url, http_post_item_t* items, size_t count, size_t max_concurrent);

/**
 * @brief 释放响应数据
 * @param resp 响应数据
 */
void http_resp_free(http_resp_t* resp);

#endif // ESURFINGCLIENT_NETCLIENT_H
