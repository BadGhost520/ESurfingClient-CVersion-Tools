#ifndef ESURFINGCLIENT_LOGGER_H
#define ESURFINGCLIENT_LOGGER_H

#include <stdio.h>

/**
 * @brief 工具版最小日志宏
 *
 * 工具界面只保留必要的警告和错误, 避免动态 ZSM 解包过程刷屏。
 */
#define LOG_DEBUG(...)   ((void)0)
#define LOG_VERBOSE(...) ((void)0)
#define LOG_INFO(...)    ((void)0)
#define LOG_WARN(...)    do { printf("[WARN] "); printf(__VA_ARGS__); printf("\n"); } while (0)
#define LOG_ERROR(...)   do { printf("[ERROR] "); printf(__VA_ARGS__); printf("\n"); } while (0)

#endif // ESURFINGCLIENT_LOGGER_H
