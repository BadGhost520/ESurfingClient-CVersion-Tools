#ifndef ESURFINGCLIENT_CIPHERINTERFACE_H
#define ESURFINGCLIENT_CIPHERINTERFACE_H

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ALGO_ID_LEN 37
#define ZSM_KEY_MAX_LEN 64
#define ZSM_IV_MAX_LEN 32

typedef struct cipherInterface
{
    char* (*encrypt)(struct cipherInterface* self, const char* text);
    char* (*decrypt)(struct cipherInterface* self, const char* hex);
    void (*destroy)(struct cipherInterface* self);
    void* private_data;
} cipher_interface_t;

typedef struct
{
    char algo_id[ALGO_ID_LEN];
    uint8_t* key;
    size_t key_len;
    uint8_t* iv;
    size_t iv_len;
    char* js;
} ios_zsm_blob_t;

extern cipher_interface_t* create_desede_ecb_cipher(
    const uint8_t* key1,
    const uint8_t* key2);

extern cipher_interface_t* create_zuc_cipher(
    const uint8_t* key,
    const uint8_t* iv);

extern cipher_interface_t* create_sm4_cbc_cipher(
    const uint8_t* key,
    const uint8_t* iv);

extern cipher_interface_t* create_sm4_ecb_cipher(
    const uint8_t* key);

extern cipher_interface_t* create_mod_xtea_iv_cipher(
    const uint32_t* key1,
    const uint32_t* key2,
    const uint32_t* key3,
    const uint32_t* iv);

extern cipher_interface_t* create_mod_xtea_cbc_triple_cipher(
    const uint32_t* key0,
    const uint32_t* key1,
    const uint32_t* key2,
    const uint32_t* iv);

extern cipher_interface_t* create_des_ecb_six_keys_cipher(
    const uint8_t* key0,
    const uint8_t* key1,
    const uint8_t* key2,
    const uint8_t* key3,
    const uint8_t* key4,
    const uint8_t* key5);

extern cipher_interface_t* create_desede_cbc_cipher(
    const uint8_t* key1,
    const uint8_t* key2,
    const uint8_t* iv1,
    const uint8_t* iv2);

// swap_key_endian: key 字是否先做 32 位字节序转换 (Linux 为 true, 旧 Android 为 false)
extern cipher_interface_t* create_mod_xtea_cipher(
    const uint32_t* key1,
    const uint32_t* key2,
    const uint32_t* key3,
    bool swap_key_endian);

// 双层 AES-128-CBC, 两层共用同一个 IV; iv == NULL 时使用全 0 IV
extern cipher_interface_t* create_aes_cbc_cipher(
    const uint8_t* key1,
    const uint8_t* key2,
    const uint8_t* iv);

extern cipher_interface_t* create_aes_ecb_cipher(
    const uint8_t* key1,
    const uint8_t* key2);

extern cipher_interface_t* create_snow3g_variant_cipher(
    const uint8_t* key,
    const uint8_t* iv);

extern cipher_interface_t* create_tea_triple_ecb_cipher(
    const uint8_t* key);

extern cipher_interface_t* create_tea_triple_cbc_cipher(
    const uint8_t* key,
    const uint8_t* iv);

extern cipher_interface_t* create_sm4_variant_cbc_cipher(
    const uint8_t* key,
    const uint8_t* iv);

extern cipher_interface_t* create_sm4_variant_ecb_cipher(
    const uint8_t* key);

extern cipher_interface_t* create_aes_double_cbc_cipher(
    const uint8_t* key,
    const uint8_t* iv);

extern cipher_interface_t* create_aes_double_ecb_cipher(
    const uint8_t* key);

extern cipher_interface_t* create_desede_double_cbc_cipher(
    const uint8_t* key,
    const uint8_t* iv);

extern cipher_interface_t* create_des_ecb_six_cipher(
    const uint8_t* key);

/**
 * @brief 设置当前加解密工厂 (会销毁旧工厂)
 * @param cipher 新的加解密工厂
 */
void cipher_set_instance(cipher_interface_t* cipher);

/**
 * @brief 判断 ticket 响应是否为 iOS PacketTunnel 动态 ZSM 模块
 * @param data ZSM 数据
 * @param length 数据长度
 * @return 是否为 iOS 动态模块
 */
bool looks_like_ios_zsm(const uint8_t* data, size_t length);

/**
 * @brief 从 iOS 动态 ZSM 解包密钥并设置加解密工厂
 * @param data ZSM 数据
 * @param length 数据长度
 * @param algo_id_out 可选, 写入 Algo-ID
 * @return 是否成功
 */
bool init_ios_cipher_from_zsm(const uint8_t* data, size_t length, char* algo_id_out);

/**
 * @brief 从 iOS 动态 ZSM 中提取 key/iv
 * @param data ZSM 数据
 * @param length 数据长度
 * @param algo_id_out 可选, 写入 Algo-ID
 * @param key_out key 输出缓冲区
 * @param key_len_out key 长度
 * @param iv_out iv 输出缓冲区
 * @param iv_len_out iv 长度 (0 表示没有 iv)
 * @param type_out 可选, 写入 cdy 算法类型 (-1 表示未解析到)
 * @return 是否成功
 */
bool get_ios_zsm_key_iv(const uint8_t* data, size_t length, char* algo_id_out,
    uint8_t* key_out, size_t* key_len_out, uint8_t* iv_out, size_t* iv_len_out,
    int8_t* type_out);

/**
 * @brief 从已解包的 iOS ZSM 数据设置加解密工厂
 * @param type cdy 算法类型
 * @param blob 解包数据
 * @return 是否成功
 */
bool init_ios_cipher_from_blob(int8_t type, ios_zsm_blob_t blob);

/**
 * @brief 从 Windows 动态 ZSM 解包密钥并设置加解密工厂
 * @param data ZSM 数据
 * @param length 数据长度
 * @param algo_id_out 可选, 写入 Algo-ID
 * @return 是否成功
 */
bool init_win_cipher_from_zsm(const uint8_t* data, size_t length, char* algo_id_out);

/**
 * @brief 从 Windows 动态 ZSM 中提取 key/iv
 * @param data ZSM 数据
 * @param length 数据长度
 * @param algo_id_out 可选, 写入 Algo-ID
 * @param key_out key 输出缓冲区
 * @param key_len_out key 长度
 * @param iv_out iv 输出缓冲区
 * @param iv_len_out iv 长度 (0 表示没有 iv)
 * @param type_out 可选, 写入 cdy 算法类型
 * @return 是否成功
 */
bool get_win_zsm_key_iv(const uint8_t* data, size_t length, char* algo_id_out,
    uint8_t* key_out, size_t* key_len_out, uint8_t* iv_out, size_t* iv_len_out,
    int8_t* type_out);

/** Android / Linux .so key 窗口的最大 key/iv 长度 */
#define ELF_SO_KEY_MAX 48
#define ELF_SO_IV_MAX 16

/**
 * @brief Android / Linux 动态算法类型
 *
 * 这些类型与 CipherFactory 里现有的 create_* 一一对应; 动态解析只负责
 * 从 .so 判断类型并传入 key/iv, 不再依赖 Algo-ID.
 */
typedef enum
{
    ELF_ALGO_UNKNOWN = -1,
    ELF_ALGO_AES_CBC = 0,        /* create_aes_cbc_cipher (双层) */
    ELF_ALGO_AES_ECB,            /* create_aes_ecb_cipher (双层) */
    ELF_ALGO_AES_DOUBLE_CBC,     /* create_aes_double_cbc_cipher */
    ELF_ALGO_AES_DOUBLE_ECB,     /* create_aes_double_ecb_cipher */
    ELF_ALGO_DESEDE_CBC,         /* create_desede_cbc_cipher */
    ELF_ALGO_DESEDE_DOUBLE_CBC,  /* create_desede_double_cbc_cipher */
    ELF_ALGO_DES6,               /* create_des_ecb_six_cipher */
    ELF_ALGO_DES6_KEYS,          /* create_des_ecb_six_keys_cipher */
    ELF_ALGO_TEA_TRIPLE_ECB,     /* create_tea_triple_ecb_cipher */
    ELF_ALGO_TEA_CBC_TRIPLE,     /* create_tea_triple_cbc_cipher */
    ELF_ALGO_MOD_XTEA,           /* create_mod_xtea_cipher */
    ELF_ALGO_MOD_XTEA_CBC_TRIPLE,/* create_mod_xtea_cbc_triple_cipher */
    ELF_ALGO_SM4_CBC,            /* create_sm4_variant_cbc_cipher */
    ELF_ALGO_SM4_ECB,            /* create_sm4_variant_ecb_cipher */
    ELF_ALGO_SNOW3G,             /* create_snow3g_variant_cipher */
    ELF_ALGO_COUNT
} elf_algo_type_t;

/**
 * @brief 从解压后的 .so 代码指纹判断算法类型 (不使用 Algo-ID)
 * @param data ELF 数据
 * @param length 数据长度
 * @param key_len key 长度
 * @param iv_len iv 长度
 * @return 算法类型, 未知返回 ELF_ALGO_UNKNOWN
 */
elf_algo_type_t elf_detect_algo_type(const uint8_t* data, size_t length,
    size_t key_len, size_t iv_len);

/**
 * @brief 按算法类型和 key/iv 创建 cipher
 * @param type 算法类型
 * @param key key 缓冲区
 * @param key_len key 长度
 * @param iv iv 缓冲区, 可为 NULL
 * @param iv_len iv 长度
 * @return cipher, 失败返回 NULL
 */
cipher_interface_t* elf_create_cipher(elf_algo_type_t type,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len);

/**
 * @brief 算法类型名称
 */
const char* elf_algo_type_name(elf_algo_type_t type);

/**
 * @brief 从 Android aarch64 动态模块 (.so) 中提取 key/iv
 * @param data ELF 数据
 * @param length 数据长度
 * @param key_out key 输出缓冲区 (至少 ELF_SO_KEY_MAX)
 * @param key_len_out key 长度
 * @param iv_out iv 输出缓冲区 (至少 ELF_SO_IV_MAX)
 * @param iv_len_out iv 长度 (0 表示该算法模块没有 iv)
 * @param type_out 可选, 输出算法类型
 * @return 是否成功
 */
bool get_android_so_key_iv(const uint8_t* data, size_t length,
    uint8_t* key_out, size_t* key_len_out,
    uint8_t* iv_out, size_t* iv_len_out,
    elf_algo_type_t* type_out);

/**
 * @brief 从 Linux x86-64 动态模块 (.so) 中提取 key/iv
 * @param data ELF 数据
 * @param length 数据长度
 * @param key_out key 输出缓冲区 (至少 ELF_SO_KEY_MAX)
 * @param key_len_out key 长度
 * @param iv_out iv 输出缓冲区 (至少 ELF_SO_IV_MAX)
 * @param iv_len_out iv 长度 (0 表示该算法模块没有 iv)
 * @param type_out 可选, 输出算法类型
 * @return 是否成功
 */
bool get_linux_so_key_iv(const uint8_t* data, size_t length,
    uint8_t* key_out, size_t* key_len_out,
    uint8_t* iv_out, size_t* iv_len_out,
    elf_algo_type_t* type_out);

/**
 * @brief 从服务器返回的 Android ZSM 容器直接解包并提取 key/iv
 * @param data ZSM 数据 (001... 容器)
 * @param length 数据长度
 * @param algo_id_out 可选, 写入容器内的 Algo-ID
 * @param key_out key 输出缓冲区 (至少 ELF_SO_KEY_MAX)
 * @param key_len_out key 长度
 * @param iv_out iv 输出缓冲区 (至少 ELF_SO_IV_MAX)
 * @param iv_len_out iv 长度
 * @param type_out 可选, 输出算法类型
 * @return 是否成功
 */
bool get_android_zsm_key_iv(const uint8_t* data, size_t length, char* algo_id_out,
    uint8_t* key_out, size_t* key_len_out,
    uint8_t* iv_out, size_t* iv_len_out,
    elf_algo_type_t* type_out);

/**
 * @brief 从服务器返回的 Linux ZSM 容器直接解包并提取 key/iv
 * @param data ZSM 数据 (001... 容器)
 * @param length 数据长度
 * @param algo_id_out 可选, 写入容器内的 Algo-ID
 * @param key_out key 输出缓冲区 (至少 ELF_SO_KEY_MAX)
 * @param key_len_out key 长度
 * @param iv_out iv 输出缓冲区 (至少 ELF_SO_IV_MAX)
 * @param iv_len_out iv 长度
 * @param type_out 可选, 输出算法类型
 * @return 是否成功
 */
bool get_linux_zsm_key_iv(const uint8_t* data, size_t length, char* algo_id_out,
    uint8_t* key_out, size_t* key_len_out,
    uint8_t* iv_out, size_t* iv_len_out,
    elf_algo_type_t* type_out);

/**
 * @brief 销毁加解密工厂
 */
void destroy_cipher_factory();

/**
 * @brief 判断 Algo-ID 是否属于固定算法表
 * @param algo_id 算法 ID
 * @return 是否属于固定算法表
 */
bool is_fixed_cipher(const char* algo_id);

/**
 * @brief 初始化加解密工厂
 * @param algo_id 算法 ID
 * @return 初始化状态
 */
bool init_cipher(const char* algo_id);

/**
 * @brief 加密函数
 * @param text 需要加密的文本
 * @return 加密后文本
 */
char* session_encrypt(const char* text);

/**
 * @brief 解密函数
 * @param text 需要解密的文本
 * @return 解密后文本
 */
char* session_decrypt(const char* text);

#endif // ESURFINGCLIENT_CIPHERINTERFACE_H
