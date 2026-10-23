#ifndef ESURFINGCLIENT_UTILS_H
#define ESURFINGCLIENT_UTILS_H

#include <stdbool.h>
#include <stddef.h>

/**
 * @brief 初始化随机数种子
 */
void init_random();

/**
 * @brief 读取一行输入, 并去掉行尾换行符
 * @param buf 缓冲区
 * @param len 缓冲区长度
 * @return 是否读取成功
 */
bool read_line(char* buf, size_t len);

/**
 * @brief 读取一行整数
 * @param value 读取结果
 * @return 是否为合法整数
 */
bool read_int(int* value);

/**
 * @brief 去掉字符串首尾空白
 * @param str 字符串
 */
void trim_str(char* str);

/**
 * @brief 生成随机 UUID (v4, 小写)
 * @param out 输出缓冲区
 * @param len 缓冲区长度 (至少 37)
 * @return 是否生成成功
 */
bool generate_uuid(char* out, size_t len);

#endif // ESURFINGCLIENT_UTILS_H
