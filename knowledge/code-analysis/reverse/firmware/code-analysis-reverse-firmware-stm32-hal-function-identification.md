---
id: code-analysis-reverse-firmware-stm32-hal-function-identification
title: STM32 HAL 固件函数识别：RCC 系统时钟计算与 GPIO BSRR digitalWrite
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: stm32-hal-function-identification
aliases:
- STM32 固件逆向
- HAL_RCC_GetSysClockFreq
- digitalWrite
- RCC PLL 计算
- GPIO BSRR
- ezFinger
tags:
- reverse
- firmware
- stm32
- hal
- gpio
- clock
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:13:42+08:00'
  notes: 已对照原文核对：RCC 0x40023808/0x40023804、SWS==HSE 返回 8MHz、非 PLL 返回 16MHz、PLLM/N/P 计算、GPIO 逻辑引脚映射与 BSRR 置位/复位语义、函数名 HAL_RCC_GetSysClockFreq 与 digitalWrite 均一致。未验证点：PoC 为按原文重写的伪代码，未在固件上复跑；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

在无符号的 STM32 固件中，可以通过寄存器地址与位域语义识别 HAL 函数：读 `RCC->CFGR` 的 SWS 位与 `RCC->PLLCFGR` 的 PLLM/N/P 计算系统时钟的函数是 `HAL_RCC_GetSysClockFreq`；通过逻辑引脚映射表查端口/引脚并写 GPIO `BSRR` 的函数是 `digitalWrite`。

## 原理

- STM32 的 RCC 寄存器是内存映射：`RCC->CFGR` 通常在 `0x40023808`，`RCC->PLLCFGR` 在 `0x40023804`。`CFGR.SWS` 位表示当前系统时钟源：`00` HSI、`01` HSE、`10` PLL。
- `HAL_RCC_GetSysClockFreq()` 的典型实现：若 SWS==HSE 返回外部晶振频率（示例 8MHz）；若 SWS!=PLL 返回 HSI（16MHz）；否则按 `PLLM/PLLN/PLLP` 计算 `PLLCLK = (HSE 或 HSI / PLLM) * PLLN / PLLP`，再除以 AHB 分频。
- GPIO 的 `BSRR` 寄存器：低 16 位写 1 置位（输出高），高 16 位写 1 复位（输出低）。`digitalWrite(pin, value)` 通常先查逻辑引脚映射表（高 4 位端口、低 4 位引脚），再写对应端口的 `BSRR`。
- 识别方法：在反汇编中搜索这些寄存器地址/常量、位掩码（`& 0xC`、`>> 6 & 0x1FF`、`& 0x3F`、`1 << (pin & 0xF)`），并与 MCU 参考手册/HAL 源码对照。
- 即使符号被剥离，寄存器访问模式、位域顺序和常量（8MHz/16MHz、PLL 分频）仍能唯一标识函数语义。

## 触发条件

- 目标是 STM32（或兼容）固件，使用 HAL/LL 库，符号被剥离。
- 反汇编中可见 RCC/GPIO 外设基地址与位域操作。
- 需要回答“某地址对应哪个 HAL 函数”或恢复固件功能。
- 有对应 MCU 系列的参考手册/HAL 源码可对照。

## 利用步骤

1. 确认 MCU 系列与外设基地址（RCC、GPIOA-G、FLASH 等）。
2. 在目标函数中搜索 `0x40023808`（CFGR）、`0x40023804`（PLLCFGR）、`0x40023800`（CR）等地址。
3. 识别 SWS/PLLSRC/PLLM/PLLN/PLLP 位域与 8MHz/16MHz 常量，匹配 `HAL_RCC_GetSysClockFreq`。
4. 搜索 GPIO `BSRR` 写入模式：`1 << (pin & 0xF)`、端口索引 `pin >> 4`、映射表数组。
5. 与 HAL 源码/参考手册交叉验证，给出函数名与语义。
6. 若函数被内联/优化，按调用关系与常量组合推断。

## PoC

```c
// 识别特征（伪代码）
uint32_t sub_8003498(void) {
    if ((RCC->CFGR & 0xC) == 4) return 8000000;    // HSE 8MHz
    if ((RCC->CFGR & 0xC) != 8) return 16000000;   // HSI 16MHz
    uint32_t pllm = (RCC->PLLCFGR >> 6) & 0x1FF;
    uint32_t plln = (RCC->PLLCFGR >> 6) & 0x1FF;   // 具体位域按系列
    // ... PLLCLK = (HSE/PLLM)*PLLN/PLLP
    return pllclk / (2 * ((RCC->CFGR >> 4 & 3) + 1));
}

void sub_8000EC0(uint32_t pin, int value) {
    int map = aInMKi[pin];                 // 逻辑引脚 -> 端口/引脚
    uint32_t port = map >> 4;
    uint32_t mask = 1 << (map & 0xF);
    GPIO_TypeDef *gpio = gpio_from_index(port);
    gpio->BSRR = value ? mask : (mask << 16);  // 置位/复位
}
```

## 变体与关联

- 变体：STM32F1/F4/H7 等系列 RCC 位域不同；LL 库函数名不同但寄存器语义一致。
- 变体：`digitalWrite` 可能使用 `ODR` 而非 `BSRR`，或先读改写。
- 变体：厂商 SDK（ESP-IDF、nRF SDK）有类似 GPIO/时钟函数，识别思路相同。
- 关联：[[code-analysis-reverse-firmware-8051-eeprom-protocol-mac]]（8051 固件）、[[code-analysis-reverse-firmware-custom-package-aes-kdf-field-recovery]]（固件加密字段）、[[code-analysis-reverse-firmware-huawei-squashfs-mips-emulation]]（固件仿真）。

## 检测与防御

- 检测：固件中 RCC/GPIO 寄存器访问模式、HAL 常量、映射表结构。
- 防御：发布固件时剥离符号、去除调试信息；对关键逻辑做混淆/内联，但无法完全隐藏外设语义。
- 响应：若需保护固件知识产权，使用安全启动/加密固件，并限制调试接口。
