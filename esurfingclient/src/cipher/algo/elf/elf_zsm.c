#include "cipher/CipherInterface.h"

#include "utils/Logger.h"

#include <7z/LzmaDec.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Android / Linux 动态算法模块 (.so) 的 key/iv 提取.
 *
 * 服务器返回的 ZSM 容器:
 *     001 <L2> <KEY> <L3> <ALGO-ID> <LZMA props 5B> <dword LE> <payload>
 *
 * L2/L3 是长度字节, 其 ASCII 值就是长度 (64='@', 36='$');
 * dword 高 4 位是加密类型, 低 28 位是解压后大小:
 *     ctype 0: 从尾部向前累积 XOR, 再 LZMA raw
 *     ctype 2: 两段固定 XTEA, 去 PKCS7, 再 LZMA raw
 *
 * 解压出来的是 ELF 模块; 可写 .data 段里有一个 256 字节的 key 窗口:
 *     window[0xFB] = key 长度 (16/24/32/48)
 *     window[0xF9] = iv 长度 (0/8/16)
 *     window[0xFE] = key 在窗口内的偏移
 *
 * key 位于 window + key_off, iv 紧跟 key. 窗口不要求 256 字节对齐,
 * 所以按字节滑动查找. key 是模块内的原始顺序; 两段式算法需要由
 * 调用方按具体算法拆分, 这里不猜算法类型.
 */

#define ELF_SO_WINDOW_SIZE 256u
#define ELF_MACHINE_X86_64 62u
#define ELF_MACHINE_AARCH64 183u
#define ELF_ZSM_MAX_UNPACKED 0x8000000u
#define ELF_ZSM_MAX_EXTRA 16u
#define ELF_ZSM_TEA_KEY "|iKFMm;FZjI6oItGmvm536xR8MJ-5C89"
#define ELF_ZSM_TEA_DELTA 0x61C88647u

/*
 * 代码指纹库: FNV-1a64(.text) -> 算法类型.
 *
 * 这里只记录"算法实现代码"的指纹, 不记录 Algo-ID. 同一个算法无论换
 * 多少个 Algo-ID, 编译出来的 .text 相同就会命中同一类型; 新编译版本
 * 指纹不匹配时返回 UNKNOWN, 交给功能 4 轮询验证.
 */
typedef struct
{
    uint64_t hash;
    elf_algo_type_t type;
} elf_algo_fingerprint_t;

static const elf_algo_fingerprint_t g_elf_algo_fingerprints[] = {
    { 0xE53646B2765C56B4ULL, ELF_ALGO_DESEDE_CBC },
    { 0x8055BF801A7F3DADULL, ELF_ALGO_AES_CBC },
    { 0xBDD6207F00646020ULL, ELF_ALGO_AES_ECB },
    { 0xEBA9DAE19BF24707ULL, ELF_ALGO_MOD_XTEA },
    { 0x0BBE4C1516B0A453ULL, ELF_ALGO_MOD_XTEA_CBC_TRIPLE },
    { 0xA38528CD834F2198ULL, ELF_ALGO_DES6_KEYS },
    { 0xCFC8BF77BF771547ULL, ELF_ALGO_SNOW3G },
    { 0x09F2A3FF84497BA4ULL, ELF_ALGO_TEA_TRIPLE_ECB },
    { 0x836DFAFAAABCDC26ULL, ELF_ALGO_TEA_CBC_TRIPLE },
    { 0x00B4485C5E439098ULL, ELF_ALGO_DESEDE_DOUBLE_CBC },
    { 0xFFE0989E9A272B15ULL, ELF_ALGO_DES6 },
    { 0xA9388EE5E4E36D5DULL, ELF_ALGO_AES_DOUBLE_CBC },
    { 0xDF723A91441504D6ULL, ELF_ALGO_SM4_CBC },
    { 0x99E1DEA036CA775DULL, ELF_ALGO_SM4_ECB },
    { 0x19B02F1C993AD487ULL, ELF_ALGO_AES_DOUBLE_ECB }
};

static uint16_t elf_rd16(const uint8_t* p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t elf_rd32(const uint8_t* p)
{
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static uint64_t elf_rd64(const uint8_t* p)
{
    return (uint64_t)elf_rd32(p) | ((uint64_t)elf_rd32(p + 4) << 32);
}

static void* elf_lzma_alloc(const ISzAllocPtr p, const size_t size)
{
    (void)p;
    return size ? malloc(size) : NULL;
}

static void elf_lzma_free(const ISzAllocPtr p, void* address)
{
    (void)p;
    free(address);
}

static const ISzAlloc g_elf_lzma_alloc = { .Alloc = elf_lzma_alloc, .Free = elf_lzma_free };

static void elf_tea_decrypt_block(const uint8_t key16[16], uint8_t block[8])
{
    uint32_t k[4];

    for (uint8_t i = 0; i < 4; i++)
    {
        k[i] = elf_rd32(key16 + (size_t)i * 4);
    }
    uint32_t v0 = elf_rd32(block);
    uint32_t v1 = elf_rd32(block + 4);
    uint32_t sum = ELF_ZSM_TEA_DELTA * (uint32_t)(-32);
    do
    {
        v1 -= ((v0 << 4) ^ (v0 >> 5)) + (k[(sum >> 11) & 3] + (v0 ^ sum));
        sum += ELF_ZSM_TEA_DELTA;
        v0 -= k[sum & 3] + (v1 ^ sum) + ((v1 << 4) ^ (v1 >> 5));
    } while (sum != 0);

    block[0] = (uint8_t)(v0);
    block[1] = (uint8_t)(v0 >> 8);
    block[2] = (uint8_t)(v0 >> 16);
    block[3] = (uint8_t)(v0 >> 24);
    block[4] = (uint8_t)(v1);
    block[5] = (uint8_t)(v1 >> 8);
    block[6] = (uint8_t)(v1 >> 16);
    block[7] = (uint8_t)(v1 >> 24);
}

static void elf_tea_decrypt_buffer(uint8_t* data, const size_t length)
{
    static const uint8_t key[] = ELF_ZSM_TEA_KEY;

    for (size_t off = 0; off + 8 <= length; off += 8)
    {
        elf_tea_decrypt_block(key, data + off);
        elf_tea_decrypt_block(key + 16, data + off);
    }
}

static bool elf_copy_uuid(char* dst, const uint8_t* src, const size_t len)
{
    if (dst == NULL || src == NULL || len != 36) return false;

    for (size_t i = 0; i < 36; i++)
    {
        const unsigned char c = src[i];
        const bool is_dash = (i == 8 || i == 13 || i == 18 || i == 23) && c == '-';
        if (!isxdigit(c) && !is_dash) return false;
        dst[i] = (char)toupper(c);
    }
    dst[36] = '\0';
    return true;
}

static uint64_t elf_fnv1a64(const uint8_t* data, const size_t length)
{
    uint64_t hash = 0xcbf29ce484222325ULL;

    for (size_t i = 0; i < length; i++)
    {
        hash ^= data[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

static bool elf_find_section(const uint8_t* data, const size_t length,
    const char* name, const uint8_t** out, size_t* out_len)
{
    const size_t shoff = (size_t)elf_rd64(data + 0x28);
    const size_t shentsize = elf_rd16(data + 0x3a);
    const size_t shnum = elf_rd16(data + 0x3c);
    const size_t shstrndx = elf_rd16(data + 0x3e);

    if (shentsize < 0x40 || shnum == 0 || shstrndx >= shnum
        || shoff > length || shnum > (length - shoff) / shentsize)
    {
        return false;
    }

    const size_t shstr = shoff + shstrndx * shentsize;
    const size_t names_off = (size_t)elf_rd64(data + shstr + 0x18);
    const size_t names_size = (size_t)elf_rd64(data + shstr + 0x20);
    if (names_off > length || names_size > length - names_off) return false;

    const char* names = (const char*)data + names_off;

    for (size_t i = 0; i < shnum; i++)
    {
        const size_t sh = shoff + i * shentsize;
        const size_t name_off = elf_rd32(data + sh);
        const uint32_t type = elf_rd32(data + sh + 4);
        const uint64_t offset = elf_rd64(data + sh + 0x18);
        const uint64_t size = elf_rd64(data + sh + 0x20);

        if (name_off >= names_size || type != 1 || offset > length || size > length - offset)
            continue;
        const char* section_name = names + name_off;
        const size_t max_name = names_size - name_off;
        if (strncmp(section_name, name, max_name) != 0) continue;

        *out = data + (size_t)offset;
        *out_len = (size_t)size;
        return true;
    }
    return false;
}

elf_algo_type_t elf_detect_algo_type(const uint8_t* data, const size_t length,
    const size_t key_len, const size_t iv_len)
{
    const uint8_t* text = NULL;
    size_t text_len = 0;

    (void)key_len;
    (void)iv_len;

    if (data == NULL || length < 0x40) return ELF_ALGO_UNKNOWN;
    if (elf_find_section(data, length, ".text", &text, &text_len) == false)
    {
        LOG_DEBUG("ELF 没有 .text 段");
        return ELF_ALGO_UNKNOWN;
    }

    const uint64_t hash = elf_fnv1a64(text, text_len);
    for (size_t i = 0; i < sizeof(g_elf_algo_fingerprints) / sizeof(g_elf_algo_fingerprints[0]); i++)
    {
        if (g_elf_algo_fingerprints[i].hash == hash)
        {
            LOG_DEBUG("ELF 代码指纹命中: %s", elf_algo_type_name(g_elf_algo_fingerprints[i].type));
            return g_elf_algo_fingerprints[i].type;
        }
    }

    LOG_DEBUG("ELF 代码指纹未命中: %016llX", (unsigned long long)hash);
    return ELF_ALGO_UNKNOWN;
}

const char* elf_algo_type_name(const elf_algo_type_t type)
{
    switch (type)
    {
    case ELF_ALGO_AES_CBC: return "AES-CBC";
    case ELF_ALGO_AES_ECB: return "AES-ECB";
    case ELF_ALGO_AES_DOUBLE_CBC: return "Double-AES-CBC";
    case ELF_ALGO_AES_DOUBLE_ECB: return "Double-AES-ECB";
    case ELF_ALGO_DESEDE_CBC: return "DESede-CBC";
    case ELF_ALGO_DESEDE_DOUBLE_CBC: return "Double-DESede-CBC";
    case ELF_ALGO_DES6: return "DES6-ECB";
    case ELF_ALGO_DES6_KEYS: return "DES6-Keys-ECB";
    case ELF_ALGO_TEA_TRIPLE_ECB: return "Triple-TEA-ECB";
    case ELF_ALGO_TEA_CBC_TRIPLE: return "Triple-TEA-CBC";
    case ELF_ALGO_MOD_XTEA: return "Modified-XTEA";
    case ELF_ALGO_MOD_XTEA_CBC_TRIPLE: return "Modified-XTEA-CBC-Triple";
    case ELF_ALGO_SM4_CBC: return "SM4-CBC";
    case ELF_ALGO_SM4_ECB: return "SM4-ECB";
    case ELF_ALGO_SNOW3G: return "SNOW3G";
    default: return "Unknown";
    }
}

cipher_interface_t* elf_create_cipher(const elf_algo_type_t type,
    const uint8_t* key, const size_t key_len,
    const uint8_t* iv, const size_t iv_len)
{
    uint32_t xtea_key[12];
    uint32_t xtea_iv[2];

    if (key == NULL)
    {
        LOG_ERROR("ELF 算法创建失败: key 为空");
        return NULL;
    }

    switch (type)
    {
    case ELF_ALGO_AES_CBC:
        if (key_len != 32 || iv_len != 16) break;
        /* Linux AES 双层的 .so 窗口带 iv, 但硬编码实现使用全 0 IV */
        return create_aes_cbc_cipher(key, key + 16, NULL);
    case ELF_ALGO_AES_ECB:
        if (key_len != 32) break;
        /* 该模块窗口里的 key 顺序是 key2+key1 */
        return create_aes_ecb_cipher(key + 16, key);
    case ELF_ALGO_AES_DOUBLE_CBC:
        if (key_len != 32 || iv_len != 16) break;
        return create_aes_double_cbc_cipher(key, iv);
    case ELF_ALGO_AES_DOUBLE_ECB:
        if (key_len != 32) break;
        return create_aes_double_ecb_cipher(key);
    case ELF_ALGO_DESEDE_CBC:
        if (key_len != 48 || iv_len != 8) break;
        return create_desede_cbc_cipher(key, key + 24, iv, iv);
    case ELF_ALGO_DESEDE_DOUBLE_CBC:
        if (key_len != 48 || iv_len != 8) break;
        return create_desede_double_cbc_cipher(key, iv);
    case ELF_ALGO_DES6:
        if (key_len != 48) break;
        return create_des_ecb_six_cipher(key);
    case ELF_ALGO_DES6_KEYS:
        if (key_len != 48) break;
        return create_des_ecb_six_keys_cipher(
            key, key + 8, key + 16, key + 24, key + 32, key + 40);
    case ELF_ALGO_TEA_TRIPLE_ECB:
        if (key_len != 48) break;
        return create_tea_triple_ecb_cipher(key);
    case ELF_ALGO_TEA_CBC_TRIPLE:
        if (key_len != 48 || iv_len != 8) break;
        return create_tea_triple_cbc_cipher(key, iv);
    case ELF_ALGO_MOD_XTEA:
        if (key_len != 48) break;
        for (size_t i = 0; i < 12; i++) xtea_key[i] = elf_rd32(key + i * 4);
        return create_mod_xtea_cipher(xtea_key, xtea_key + 4, xtea_key + 8, true);
    case ELF_ALGO_MOD_XTEA_CBC_TRIPLE:
        if (key_len != 48 || iv_len != 8) break;
        for (size_t i = 0; i < 12; i++) xtea_key[i] = elf_rd32(key + i * 4);
        for (size_t i = 0; i < 2; i++) xtea_iv[i] = elf_rd32(iv + i * 4);
        return create_mod_xtea_cbc_triple_cipher(
            xtea_key, xtea_key + 4, xtea_key + 8, xtea_iv);
    case ELF_ALGO_SM4_CBC:
        if (key_len != 16 || iv_len != 16) break;
        return create_sm4_variant_cbc_cipher(key, iv);
    case ELF_ALGO_SM4_ECB:
        if (key_len != 16) break;
        return create_sm4_variant_ecb_cipher(key);
    case ELF_ALGO_SNOW3G:
        if (key_len != 16 || iv_len != 16) break;
        return create_snow3g_variant_cipher(key, iv);
    default:
        LOG_ERROR("ELF 算法类型未知");
        return NULL;
    }

    LOG_ERROR("ELF 算法参数不匹配: %s key_len=%zu iv_len=%zu",
        elf_algo_type_name(type), key_len, iv_len);
    return NULL;
}

static bool key_bytes_plausible(const uint8_t* key, const size_t key_len)
{
    size_t printable = 0;

    for (size_t i = 0; i < key_len; i++)
    {
        if (key[i] >= 0x20 && key[i] <= 0x7e) printable++;
    }
    /* 样本 key 全部是可打印 ASCII, 用 80% 过滤明显不是 key 的随机字节 */
    return printable * 5 >= key_len * 4;
}

static bool elf_find_key_window(const uint8_t* data, const size_t length,
    const uint16_t expected_machine, const char* platform,
    uint8_t* key_out, size_t* key_len_out,
    uint8_t* iv_out, size_t* iv_len_out)
{
    uint8_t best_key[ELF_SO_KEY_MAX];
    uint8_t best_iv[ELF_SO_IV_MAX];
    size_t best_key_len = 0;
    size_t best_iv_len = 0;
    size_t best_score = 0;
    bool found = false;

    if (data == NULL || length < 0x40 || key_out == NULL || key_len_out == NULL
        || iv_out == NULL || iv_len_out == NULL)
    {
        return false;
    }
    if (data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F')
    {
        LOG_ERROR("%s 模块不是 ELF", platform);
        return false;
    }
    if (data[4] != 2 || data[5] != 1)
    {
        LOG_ERROR("%s 模块不是 ELF64 小端", platform);
        return false;
    }
    if (elf_rd16(data + 0x12) != expected_machine)
    {
        LOG_ERROR("%s 模块架构不匹配: %u", platform, elf_rd16(data + 0x12));
        return false;
    }

    const size_t shoff = (size_t)elf_rd64(data + 0x28);
    const size_t shentsize = elf_rd16(data + 0x3a);
    const size_t shnum = elf_rd16(data + 0x3c);

    if (shentsize < 0x40 || shnum == 0 || shoff > length
        || shnum > (length - shoff) / shentsize)
    {
        LOG_ERROR("%s 模块 section header 非法", platform);
        return false;
    }

    for (size_t i = 0; i < shnum; i++)
    {
        const size_t sh = shoff + i * shentsize;
        const uint32_t type = elf_rd32(data + sh + 4);
        const uint64_t flags = elf_rd64(data + sh + 8);
        const uint64_t offset = elf_rd64(data + sh + 0x18);
        const uint64_t size = elf_rd64(data + sh + 0x20);

        /* key 窗口在可写 PROGBITS 段 (.data/.data.rel.ro) */
        if (type != 1 || (flags & 1u) == 0 || offset > length || size > length - offset
            || size < ELF_SO_WINDOW_SIZE)
        {
            continue;
        }

        const uint8_t* section = data + (size_t)offset;

        for (size_t pos = 0; pos + ELF_SO_WINDOW_SIZE <= size; pos++)
        {
            const uint8_t* window = section + pos;
            const size_t key_len = window[0xfb];
            const size_t iv_len = window[0xf9];
            const size_t key_off = window[0xfe];

            if (key_len != 16 && key_len != 24 && key_len != 32 && key_len != 48)
                continue;
            if (iv_len != 0 && iv_len != 8 && iv_len != 16)
                continue;
            if (key_off == 0 || key_off + key_len + iv_len > 0xf9)
                continue;
            if (!key_bytes_plausible(window + key_off, key_len))
                continue;

            size_t printable = 0;
            for (size_t k = 0; k < key_len; k++)
            {
                if (window[key_off + k] >= 0x20 && window[key_off + k] <= 0x7e) printable++;
            }
            const size_t score = printable * 100 + key_off + key_len;
            if (found && score <= best_score) continue;

            memcpy(best_key, window + key_off, key_len);
            if (iv_len > 0) memcpy(best_iv, window + key_off + key_len, iv_len);
            best_key_len = key_len;
            best_iv_len = iv_len;
            best_score = score;
            found = true;

            LOG_DEBUG("%s key 窗口: section+0x%zx key_len=%zu iv_len=%zu key_off=%zu",
                platform, pos, key_len, iv_len, key_off);
        }
    }

    if (found == false)
    {
        LOG_ERROR("%s 模块中没有找到 key 窗口", platform);
        return false;
    }

    memcpy(key_out, best_key, best_key_len);
    *key_len_out = best_key_len;
    if (best_iv_len > 0) memcpy(iv_out, best_iv, best_iv_len);
    *iv_len_out = best_iv_len;
    return true;
}

static bool elf_unpack_zsm(const uint8_t* data, const size_t length,
    char* algo_id_out, uint8_t** unpacked_out, size_t* unpacked_len_out)
{
    uint8_t* cipher = NULL;
    uint8_t* unpacked = NULL;

    if (data == NULL || length < 15 || unpacked_out == NULL || unpacked_len_out == NULL)
    {
        return false;
    }
    if (memcmp(data, "001", 3) != 0)
    {
        LOG_ERROR("ELF ZSM 缺少 001 头");
        return false;
    }

    size_t offset = 3;
    const size_t key_len = data[offset++];
    if (offset + key_len + 1 > length)
    {
        LOG_ERROR("ELF ZSM key 头越界");
        return false;
    }
    offset += key_len;

    const size_t algo_len = data[offset++];
    if (algo_len != 36 || offset + algo_len + 9 > length)
    {
        LOG_ERROR("ELF ZSM Algo-ID 头非法: len=%zu", algo_len);
        return false;
    }
    if (algo_id_out != NULL)
    {
        if (!elf_copy_uuid(algo_id_out, data + offset, algo_len))
        {
            snprintf(algo_id_out, ALGO_ID_LEN, "00000000-0000-0000-0000-000000000000");
        }
    }
    offset += algo_len;

    const uint8_t* props = data + offset;
    const uint32_t packed = elf_rd32(props + 5);
    const uint32_t ctype = packed >> 28;
    const uint32_t unpacked_size = packed & 0x0FFFFFFFu;
    if ((ctype != 0 && ctype != 2) || unpacked_size == 0
        || unpacked_size > ELF_ZSM_MAX_UNPACKED)
    {
        LOG_ERROR("ELF ZSM packed 头非法: ctype=%u size=%u", ctype, unpacked_size);
        return false;
    }

    const size_t cipher_len = length - offset - 9;
    if (cipher_len < 8)
    {
        LOG_ERROR("ELF ZSM 密文太短: %zu", cipher_len);
        return false;
    }

    cipher = malloc(cipher_len);
    if (cipher == NULL) return false;
    memcpy(cipher, props + 9, cipher_len);

    SizeT src_len = cipher_len;
    if (ctype == 0)
    {
        /* ctype 0: 从最后一个字节向前累积 XOR */
        for (size_t i = cipher_len - 1; i > 0; i--)
        {
            cipher[i - 1] ^= cipher[i];
        }
    }
    else
    {
        elf_tea_decrypt_buffer(cipher, cipher_len);
        const uint8_t pad = cipher[cipher_len - 1];
        if (pad < 1 || pad > 16 || pad > cipher_len)
        {
            LOG_ERROR("ELF ZSM XTEA 填充非法: %u", pad);
            free(cipher);
            return false;
        }
        src_len -= pad;
    }

    /* 样本里 ctype 0 的 size 偶尔比实际输出少 1 字节, 留一点余量 */
    const size_t capacity = (size_t)unpacked_size + ELF_ZSM_MAX_EXTRA;
    unpacked = calloc(1, capacity);
    if (unpacked == NULL)
    {
        free(cipher);
        return false;
    }

    SizeT dest_len = capacity;
    ELzmaStatus status;
    const SRes lzma_ret = LzmaDecode(unpacked, &dest_len, cipher, &src_len,
        props, 5, LZMA_FINISH_ANY, &status, &g_elf_lzma_alloc);
    free(cipher);

    /* 容器没有标准 LZMA 结束标记的样本会返回 INPUT_EOF, 输出仍完整 */
    if ((lzma_ret != SZ_OK && lzma_ret != SZ_ERROR_INPUT_EOF
            && lzma_ret != SZ_ERROR_OUTPUT_EOF)
        || dest_len < unpacked_size)
    {
        LOG_ERROR("ELF ZSM LZMA 解压失败: ret=%d out=%zu want=%u",
            lzma_ret, (size_t)dest_len, unpacked_size);
        free(unpacked);
        return false;
    }

    *unpacked_out = unpacked;
    *unpacked_len_out = (size_t)dest_len;
    return true;
}

bool get_android_so_key_iv(const uint8_t* data, const size_t length,
    uint8_t* key_out, size_t* key_len_out,
    uint8_t* iv_out, size_t* iv_len_out,
    elf_algo_type_t* type_out)
{
    const bool ok = elf_find_key_window(data, length, ELF_MACHINE_AARCH64, "Android",
        key_out, key_len_out, iv_out, iv_len_out);
    if (ok && type_out != NULL)
        *type_out = elf_detect_algo_type(data, length, *key_len_out, *iv_len_out);
    return ok;
}

bool get_linux_so_key_iv(const uint8_t* data, const size_t length,
    uint8_t* key_out, size_t* key_len_out,
    uint8_t* iv_out, size_t* iv_len_out,
    elf_algo_type_t* type_out)
{
    const bool ok = elf_find_key_window(data, length, ELF_MACHINE_X86_64, "Linux",
        key_out, key_len_out, iv_out, iv_len_out);
    if (ok && type_out != NULL)
        *type_out = elf_detect_algo_type(data, length, *key_len_out, *iv_len_out);
    return ok;
}

bool get_android_zsm_key_iv(const uint8_t* data, const size_t length, char* algo_id_out,
    uint8_t* key_out, size_t* key_len_out,
    uint8_t* iv_out, size_t* iv_len_out,
    elf_algo_type_t* type_out)
{
    uint8_t* unpacked = NULL;
    size_t unpacked_len = 0;

    if (!elf_unpack_zsm(data, length, algo_id_out, &unpacked, &unpacked_len)) return false;

    const bool ok = elf_find_key_window(unpacked, unpacked_len, ELF_MACHINE_AARCH64, "Android",
        key_out, key_len_out, iv_out, iv_len_out);
    if (ok && type_out != NULL)
        *type_out = elf_detect_algo_type(unpacked, unpacked_len, *key_len_out, *iv_len_out);
    free(unpacked);
    return ok;
}

bool get_linux_zsm_key_iv(const uint8_t* data, const size_t length, char* algo_id_out,
    uint8_t* key_out, size_t* key_len_out,
    uint8_t* iv_out, size_t* iv_len_out,
    elf_algo_type_t* type_out)
{
    uint8_t* unpacked = NULL;
    size_t unpacked_len = 0;

    if (!elf_unpack_zsm(data, length, algo_id_out, &unpacked, &unpacked_len)) return false;

    const bool ok = elf_find_key_window(unpacked, unpacked_len, ELF_MACHINE_X86_64, "Linux",
        key_out, key_len_out, iv_out, iv_len_out);
    if (ok && type_out != NULL)
        *type_out = elf_detect_algo_type(unpacked, unpacked_len, *key_len_out, *iv_len_out);
    free(unpacked);
    return ok;
}
