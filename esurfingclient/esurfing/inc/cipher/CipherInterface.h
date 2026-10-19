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

extern cipher_interface_t* create_aes_cbc_android_old_cipher(
    const uint8_t* key1,
    const uint8_t* key2,
    const uint8_t* iv);

extern cipher_interface_t* create_aes_ecb_android_old_cipher(
    const uint8_t* key1,
    const uint8_t* key2);

extern cipher_interface_t* create_desede_cbc_android_old_cipher(
    const uint8_t* key1,
    const uint8_t* key2,
    const uint8_t* iv1,
    const uint8_t* iv2);

extern cipher_interface_t* create_desede_ecb_android_old_cipher(
    const uint8_t* key1,
    const uint8_t* key2);

extern cipher_interface_t* create_zuc_android_old_cipher(
    const uint8_t* key,
    const uint8_t* iv);

extern cipher_interface_t* create_sm4_cbc_android_old_cipher(
    const uint8_t* key,
    const uint8_t* iv);

extern cipher_interface_t* create_sm4_ecb_android_old_cipher(
    const uint8_t* key);

extern cipher_interface_t* create_mod_xtea_android_old_cipher(
    const uint32_t* key1,
    const uint32_t* key2,
    const uint32_t* key3);

extern cipher_interface_t* create_mod_xtea_iv_android_old_cipher(
    const uint32_t* key1,
    const uint32_t* key2,
    const uint32_t* key3,
    const uint32_t* iv);

extern cipher_interface_t* create_ab6c8_linux_cipher(
    const uint32_t* key0,
    const uint32_t* key1,
    const uint32_t* key2,
    const uint32_t* iv);

extern cipher_interface_t* create_des_ecb_six_linux_cipher(
    const uint8_t* key0,
    const uint8_t* key1,
    const uint8_t* key2,
    const uint8_t* key3,
    const uint8_t* key4,
    const uint8_t* key5);

extern cipher_interface_t* create_desede_cbc_linux_cipher(
    const uint8_t* key1,
    const uint8_t* key2,
    const uint8_t* iv1,
    const uint8_t* iv2);

extern cipher_interface_t* create_mod_xtea_linux_cipher(
    const uint32_t* key1,
    const uint32_t* key2,
    const uint32_t* key3);

extern cipher_interface_t* create_aes_cbc_linux_cipher(
    const uint8_t* key1,
    const uint8_t* key2);

extern cipher_interface_t* create_aes_ecb_linux_cipher(
    const uint8_t* key1,
    const uint8_t* key2);

extern cipher_interface_t* create_snow3g_variant_android_cipher(
    const uint8_t* key,
    const uint8_t* iv);

extern cipher_interface_t* create_tea_triple_ecb_android_cipher(
    const uint8_t* key);

extern cipher_interface_t* create_tea_triple_cbc_android_cipher(
    const uint8_t* key,
    const uint8_t* iv);

extern cipher_interface_t* create_sm4_variant_cbc_android_cipher(
    const uint8_t* key,
    const uint8_t* iv);

extern cipher_interface_t* create_sm4_variant_ecb_android_cipher(
    const uint8_t* key);

extern cipher_interface_t* create_aes_double_cbc_android_cipher(
    const uint8_t* key,
    const uint8_t* iv);

extern cipher_interface_t* create_aes_double_ecb_android_cipher(
    const uint8_t* key);

extern cipher_interface_t* create_desede_double_cbc_android_cipher(
    const uint8_t* key,
    const uint8_t* iv);

extern cipher_interface_t* create_des_ecb_six_android_cipher(
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
 * @return 是否成功
 */
bool get_ios_zsm_key_iv(const uint8_t* data, size_t length, char* algo_id_out,
    uint8_t* key_out, size_t* key_len_out, uint8_t* iv_out, size_t* iv_len_out);

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
 * @return 是否成功
 */
bool get_win_zsm_key_iv(const uint8_t* data, size_t length, char* algo_id_out,
    uint8_t* key_out, size_t* key_len_out, uint8_t* iv_out, size_t* iv_len_out);

/**
 * @brief 销毁加解密工厂
 */
void destroy_cipher_factory();

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
