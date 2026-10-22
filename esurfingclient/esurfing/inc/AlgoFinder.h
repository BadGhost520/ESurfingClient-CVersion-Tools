#ifndef ESURFINGCLIENT_ALGOFINDER_H
#define ESURFINGCLIENT_ALGOFINDER_H

#include <stdbool.h>
#include <stddef.h>

/** @brief 连续多少次没有新 Algo-ID 时停止 */
#ifndef ALGO_FIND_NO_NEW_LIMIT
#define ALGO_FIND_NO_NEW_LIMIT 1000
#endif

/** @brief UA 缓冲区长度 */
#define ALGO_UA_LEN 128

/**
 * @brief 提示选择/输入 UA
 * @param ua UA 输出缓冲区
 * @param ua_len 缓冲区长度
 * @return 是否选择成功 (输入 0 返回主菜单时返回 false)
 */
bool algo_prompt_ua(char* ua, size_t ua_len);

/**
 * @brief 进入 Algo-ID 查找流程 (可选择是否导出 Key/IV)
 */
void algo_finder_run();

/**
 * @brief 循环请求 ticket 接口, 直到响应中的 Algo-ID 与目标一致
 * @param ua 请求使用的 UA
 * @param target_algo_id 目标 Algo-ID
 * @param max_attempts 最多查找次数, 0 表示一直查找
 * @param out_body 匹配到的 ZSM 数据 (由调用方 free)
 * @param out_size ZSM 数据长度
 * @return 是否匹配成功
 */
bool algo_fetch_matching_zsm(const char* ua, const char* target_algo_id, size_t max_attempts,
    char** out_body, size_t* out_size);

/** @brief 一次 ticket 采样结果 (body 由调用方 free) */
typedef struct
{
    char algo_id[64];
    char client_id[64];
    char* body;
    size_t body_size;
} ticket_sample_t;

/**
 * @brief 并发请求一批 ticket, 返回 ZSM 样本
 * @param ua 请求 UA
 * @param count 本批请求数
 * @param out 样本数组 (至少 count 项)
 * @param out_count 实际成功样本数
 * @return 是否至少得到一个样本
 */
bool algo_fetch_ticket_samples(const char* ua, size_t count, ticket_sample_t* out, size_t* out_count);

/**
 * @brief 获取默认 ticket URL
 * @return ticket URL
 */
const char* algo_ticket_url(void);

#endif // ESURFINGCLIENT_ALGOFINDER_H
