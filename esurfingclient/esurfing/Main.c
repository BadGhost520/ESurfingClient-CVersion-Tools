#include "AlgoFinder.h"
#include "NetClient.h"
#include "cipher/CipherInterface.h"
#include "utils/Utils.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALGO_ID_INPUT_LEN 64
#define TEXT_INPUT_LEN 8192
#define CHOICE_LEN 16

/**
 * @brief 打印主菜单
 */
static void print_menu()
{
    printf("\n请选择工具功能:\n");
    printf("  1. 加解密文本\n");
    printf("  2. 查找 Algo-ID / 导出 Key/IV\n");
    printf("  0. 退出\n");
    printf("请输入选项: ");
}

/**
 * @brief 将字符串转为大写
 * @param str 字符串
 */
static void to_upper_str(char* str)
{
    if (str == NULL) return;

    for (size_t i = 0; str[i] != '\0'; i++)
    {
        str[i] = (char)toupper((unsigned char)str[i]);
    }
}

/**
 * @brief 提示动态 ZSM 匹配的最大查找次数
 * @param max_attempts 次数 (0 表示一直查找)
 * @return 是否输入成功
 */
static bool prompt_max_attempts(size_t* max_attempts)
{
    char line[32];

    if (max_attempts == NULL) return false;

    for (;;)
    {
        printf("\n最多查找次数 (直接回车默认 1000, 输入 0 一直查找, Ctrl+C 停止): ");
        if (read_line(line, sizeof(line)) == false) return false;

        trim_str(line);
        if (line[0] == '\0')
        {
            *max_attempts = 1000;
            return true;
        }

        char* end = NULL;
        const long value = strtol(line, &end, 10);
        if (end == line || *end != '\0' || value < 0)
        {
            printf("输入无效\n");
            continue;
        }

        *max_attempts = (size_t)value;
        return true;
    }
}

/**
 * @brief 从 ticket 接口获取与 Algo-ID 匹配的 ZSM 并初始化动态加解密工厂
 * @param algo_id 目标 Algo-ID
 * @return 是否初始化成功
 */
static bool init_dynamic_cipher(const char* algo_id)
{
    char ua[ALGO_UA_LEN];
    char* zsm = NULL;
    size_t zsm_size = 0;
    size_t max_attempts = 0;
    bool ok = false;

    printf("固定算法表中没有该 Algo-ID, 尝试从 ticket 接口获取动态 ZSM...\n");

    if (algo_prompt_ua(ua, sizeof(ua)) == false) return false;
    if (prompt_max_attempts(&max_attempts) == false) return false;
    if (algo_fetch_matching_zsm(ua, algo_id, max_attempts, &zsm, &zsm_size) == false) return false;

    if (strstr(ua, "WinSVR") != NULL)
    {
        ok = init_win_cipher_from_zsm((const uint8_t*)zsm, zsm_size, NULL);
        if (ok == false)
        {
            printf("Windows ZSM 解析失败, 尝试按 iOS/macOS 动态 ZSM 解析...\n");
            ok = init_ios_cipher_from_zsm((const uint8_t*)zsm, zsm_size, NULL);
        }
    }
    else if (strstr(ua, "iOSdy") != NULL || strstr(ua, "macdy") != NULL)
    {
        ok = init_ios_cipher_from_zsm((const uint8_t*)zsm, zsm_size, NULL);
    }
    else
    {
        printf("该 UA 不是 iOS/Windows 动态通道, 无法解析动态 ZSM\n");
    }

    free(zsm);

    if (ok == false)
    {
        printf("动态 ZSM 解析失败\n");
        return false;
    }

    printf("动态 ZSM 解析成功 (ZSM %zu 字节)\n", zsm_size);
    return true;
}

/**
 * @brief 选择加密/解密操作
 * @param choice 输出选项
 * @return 是否读取成功
 */
static bool prompt_cipher_operation(char* choice)
{
    for (;;)
    {
        printf("\n请选择操作:\n");
        printf("  1. 加密\n");
        printf("  2. 解密\n");
        printf("  0. 返回\n");
        printf("请输入选项: ");
        if (read_line(choice, CHOICE_LEN) == false) return false;

        trim_str(choice);
        if (strcmp(choice, "0") == 0 || strcmp(choice, "1") == 0 || strcmp(choice, "2") == 0)
        {
            return true;
        }
        printf("输入无效, 请重新选择\n");
    }
}

/**
 * @brief 询问是否继续使用当前 Algo-ID
 * @return true 继续, false 返回主菜单
 */
static bool prompt_continue_same_algo(void)
{
    char line[CHOICE_LEN];

    for (;;)
    {
        printf("\n是否继续使用同一个 Algo-ID 进行加解密? (y/N): ");
        if (read_line(line, sizeof(line)) == false) return false;

        trim_str(line);
        if (line[0] == '\0' || (line[1] == '\0' && (line[0] == 'n' || line[0] == 'N')))
        {
            return false;
        }
        if (line[1] == '\0' && (line[0] == 'y' || line[0] == 'Y'))
        {
            return true;
        }
        printf("输入无效, 请输入 y 或 n\n");
    }
}

/**
 * @brief 文本加解密流程
 */
static void cipher_tool()
{
    char algo_id[ALGO_ID_INPUT_LEN];
    char choice[CHOICE_LEN];
    char text[TEXT_INPUT_LEN];

    printf("\n请输入 Algo-ID: ");
    if (read_line(algo_id, sizeof(algo_id)) == false) return;

    trim_str(algo_id);
    to_upper_str(algo_id);
    if (algo_id[0] == '\0')
    {
        printf("Algo-ID 不能为空\n");
        return;
    }

    if (prompt_cipher_operation(choice) == false) return;
    if (strcmp(choice, "0") == 0) return;

    if (init_cipher(algo_id) == false)
    {
        if (init_dynamic_cipher(algo_id) == false)
        {
            printf("未能使用该 Algo-ID, 返回主菜单\n");
            return;
        }
    }

    for (;;)
    {
        char* result;

        printf("请输入要%s的文本: ", strcmp(choice, "1") == 0 ? "加密" : "解密");
        if (read_line(text, sizeof(text)) == false) break;

        if (strcmp(choice, "1") == 0) result = session_encrypt(text);
        else result = session_decrypt(text);

        if (result == NULL)
        {
            printf("处理失败, 请检查 Algo-ID 与输入内容\n");
        }
        else
        {
            printf("%s后的文本:\n%s\n", strcmp(choice, "1") == 0 ? "加密" : "解密", result);
            free(result);
        }

        if (prompt_continue_same_algo() == false) break;
        if (prompt_cipher_operation(choice) == false) break;
        if (strcmp(choice, "0") == 0) break;
    }

    destroy_cipher_factory();
}

int main()
{
#ifdef _WIN32
    system("chcp 65001 >nul");
#endif

    init_random();

    if (http_global_init() == false)
    {
        printf("初始化网络环境失败\n");
        return 1;
    }

    printf("ESurfingClient 工具 " PROGRAM_FULL_VERSION "\n");

    for (;;)
    {
        char choice[CHOICE_LEN];

        print_menu();
        if (read_line(choice, sizeof(choice)) == false) break;

        trim_str(choice);
        if (strcmp(choice, "1") == 0)
        {
            cipher_tool();
        }
        else if (strcmp(choice, "2") == 0)
        {
            algo_finder_run();
        }
        else if (strcmp(choice, "0") == 0)
        {
            break;
        }
        else
        {
            printf("输入无效, 请重新选择\n");
        }
    }

    http_global_cleanup();
    printf("已退出\n");
    return 0;
}
