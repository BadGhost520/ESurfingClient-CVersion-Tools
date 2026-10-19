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
 * @brief 进入 Algo-ID 查找流程 (包含交互提示)
 */
void algo_finder_run();

/**
 * @brief 查找 Algo-ID 并解析动态 ZSM 中的 key/iv, 导出到 txt 文件
 */
void algo_key_iv_run(void);

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

#endif // ESURFINGCLIENT_ALGOFINDER_H
