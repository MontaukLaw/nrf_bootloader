#include "nrf_bootloader_fw_activation.h"
#include "nrf_dfu_settings.h"
#include "nrf_dfu_mbr.h"
#include "nrf_bootloader_info.h"
#include "crc32.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_dfu_utils.h"
#include "nrf_bootloader_wdt.h"

// 每page大小是4096字节
#define BYTES_FOR_ONE_PAGE 4096
// 加密字节数240字节
#define ENCRYPT_BYTES 240

// uint32_t flash_ram_buf[BYTES_FOR_ONE_PAGE / sizeof(uint32_t)];
uint8_t flash_ram_buf[BYTES_FOR_ONE_PAGE];

// u8格式加密长度为240
#define MAX_ENCRYPTED_LEN_U8 240
// u32格式解密长度为60
#define MAX_DECRYPTED_LEN_U32 60

extern uint8_t start_write_hex;
static uint32_t key_buffer[4] = {0, 0, 0, 0};
// 密钥是128bit的，4个uint32
static uint32_t init_key[4] = {0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210};
static uint32_t drift[4] = {0x12341234, 0x567890ab, 0xcdef1122, 0x33445566};
// static uint32_t decrypted_buf[2];
static uint16_t package_counter = 0;
static uint8_t decrpyted_data[MAX_ENCRYPTED_LEN_U8];

static void tea_decrypt(uint32_t *v, uint32_t *k, uint8_t *decrypted_buf)
{
    uint32_t v0 = v[0], v1 = v[1], sum = 0xC6EF3720, i;  /* set up */
    uint32_t delta = 0x9e3779b9;                         /* a key schedule constant */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3]; /* cache key */
    for (i = 0; i < 32; i++)
    { /* basic cycle start */
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    } /* end cycle */

    // decrypted_buf[0] = v0;
    // decrypted_buf[4] = v1;
    // memcpy(&decrypted_buf[0], &v0, 4);
    // memcpy(&decrypted_buf[4], &v1, 4);
    // decrypted_buf[0] = v0;
    // decrypted_buf[1] = v1;

    // 做个大小端变换
    decrypted_buf[0] = (v0 >> 24) & 0xff;
    decrypted_buf[1] = (v0 >> 16) & 0xff;
    decrypted_buf[2] = (v0 >> 8) & 0xff;
    decrypted_buf[3] = v0 & 0xff;

    decrypted_buf[4] = (v1 >> 24) & 0xff;
    decrypted_buf[5] = (v1 >> 16) & 0xff;
    decrypted_buf[6] = (v1 >> 8) & 0xff;
    decrypted_buf[7] = v1 & 0xff;
}

// 更新密钥,方法是将密钥的每个字节加上一个固定的值
static void update_key(uint32_t v0, uint32_t v1)
{
    key_buffer[0] = key_buffer[0] + drift[0] + v0;
    key_buffer[1] = key_buffer[1] + drift[1] + v1;
    key_buffer[2] = key_buffer[2] + drift[2] + v0;
    key_buffer[3] = key_buffer[3] + drift[3] + v1;
}

static void decrypt_hex(const uint8_t *p_data, uint8_t *decrypted)
{
    uint8_t i;
    // 4*15 = 60
    // 缓存
    uint32_t data_buf[60];

    for (i = 0; i < MAX_ENCRYPTED_LEN_U8; i = i + 4)
    {
        data_buf[i / 4] = (p_data[i] << 24) | (p_data[i + 1] << 16) | (p_data[i + 2] << 8) | p_data[i + 3];
    }

    memcpy(key_buffer, init_key, 4 * sizeof(uint32_t));

    NRF_LOG_DEBUG("Before decrypt:");
    // 仅仅打印前面6个字节
    for (i = 0; i < 6; i++)
    {
        NRF_LOG_DEBUG("0x%08x", data_buf[i]);
    }

    for (i = 0; i < MAX_DECRYPTED_LEN_U32; i = i + 2)
    {
        tea_decrypt(&data_buf[i], key_buffer, &decrypted[i * 4]);
        // NRF_LOG_DEBUG("After decrypt: %08x %08x", decrypted_buf[0], decrypted_buf[1]);
        update_key(data_buf[i], data_buf[i + 1]);
        // NRF_LOG_DEBUG("After update key: %08x %08x %08x %08x", key_buffer[0], key_buffer[1], key_buffer[2], key_buffer[3]);
    }

    NRF_LOG_DEBUG("After decrypt:");
    NRF_LOG_HEXDUMP_DEBUG(decrypted, 80);
    NRF_LOG_HEXDUMP_DEBUG(&decrypted[80], 80);
    NRF_LOG_HEXDUMP_DEBUG(&decrypted[160], 80);
}

void decrypt_hex_from_flash(const uint8_t *p_data)
{
    // 第一步, 把flash数据复制到内存中
    memcpy(flash_ram_buf, p_data, BYTES_FOR_ONE_PAGE);

    NRF_LOG_DEBUG("flash_ram_buf 300+16");
    NRF_LOG_HEXDUMP_DEBUG(&flash_ram_buf[300], 16);
    // cpy_flash_to_ram((uint32_t)p_data, flash_ram_buf, BYTES_FOR_ONE_PAGE);

    // 第二步, 解密前面的
    decrypt_hex(flash_ram_buf, decrpyted_data);

    // 第三步, 把解密后的数据复制回内存
    memcpy(flash_ram_buf, decrpyted_data, ENCRYPT_BYTES);

    NRF_LOG_DEBUG("flash_ram_buf 0+80");
    // 打印一下flash_ram_buf
    NRF_LOG_HEXDUMP_DEBUG(flash_ram_buf, 80);

    NRF_LOG_DEBUG("flash_ram_buf 300+16");
    NRF_LOG_HEXDUMP_DEBUG(&flash_ram_buf[300], 16);

    // 第四步, 删除page1的数据
    nrf_dfu_flash_erase(nrf_dfu_bank0_start_addr(), 1, NULL);

    // 第五步, 把解密后的数据写回page1, bank0
    nrf_dfu_flash_store(nrf_dfu_bank0_start_addr(), (uint32_t *)flash_ram_buf, BYTES_FOR_ONE_PAGE, NULL);
}

static void decrypt_ram_data(void)
{
    for (int i = 0; i < BYTES_FOR_ONE_PAGE / sizeof(uint32_t); i++)
    {
        // 测试
        // flash_ram_buf[i] = flash_ram_buf[i] + 1;
        // flash_ram_buf[i] = i;
    }
}

void cpy_flash_to_ram(uint32_t src_addr, uint32_t *dst_addr, uint32_t size)
{
    uint32_t *p_src = (uint32_t *)src_addr;
    uint32_t *p_dst = dst_addr;
    uint32_t *p_end = p_dst + size / sizeof(uint32_t);

    while (p_dst < p_end)
    {
        *p_dst = *p_src;
        p_dst++;
        p_src++;
    }
}
