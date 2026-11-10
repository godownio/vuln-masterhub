---
id: ctf-reverse-harmonyos-pattern-lock-napi-xxtea-recover
title: HarmonyOS 手势锁逆向：N-API verifyPattern 校验 + XXTEA 解 9 元组恢复解锁顺序
type: scenario
domain: ctf
path: ctf/reverse
technique: harmonyos-pattern-lock-napi-xxtea-recover
tags:
- ctf
- reverse
- harmonyos
- arkts
- napi
- native
- xxtea
- pattern-lock
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-19
  verified_at: '2026-11-08T12:12:37+08:00'
  notes: 已对照原文核对：img27/28 确认 ArkTS 侧 verifyPattern 来自 libsecret.so 且先判 INPUT_LENGTH=9（img29），img31/32 确认 N-API 读 9 个 int32 后 XXTEA 加密并与 is 数据逐项比对；img33/34 确认 key=what{0xB,0x2D,0xE,0x1BF52}、密文=is（小端），img35/36 确认 get_wide_dword 提取值，img37 确认解密输出 134507286 即手势顺序。C 解密程序完整可复现，PoC 完整。未验证点：未在本机重跑。
url: /docs/ctf/reverse/ctf-reverse-harmonyos-pattern-lock-napi-xxtea-recover/
draft: false
kb_aliases:
- HarmonyOS 手势密码还原
- libsecret.so verifyPattern
- PatternLock 默认密码是诱饵
- XXTEA 9 个 DWORD
- 九宫格 9 点顺序还原
---

## 一句话结论

HarmonyOS 应用把手势锁校验放进 native 库：ArkTS 侧只判长度再调 `verifyPattern`，真正逻辑是 N-API 读出 9 个整数、先用 XXTEA 就地加密再与 `.data` 中的 9 个 DWORD 逐项比较；把比较用的密文按同一 key 做 XXTEA 解密，即得到用户必须输入的 9 点顺序（本题为 `1 3 4 5 0 7 2 8 6`，拼成密码 `134507286`）。

## 原理

- **分层结构**：页面 `lock.mjs` 只做 UI 与长度检查（`INPUT_LENGTH = 9`），随后 `import verifyPattern_ from '@normalized:Y&&&libsecret.so&.mjs'` 调 native。ArkTS 层的 `defaultPassword = '0,1,2,3,4,5,6,7,8'` 只是初始化点阵用的默认值，不参与校验，属于诱饵。
- **定位导出函数**：`libsecret.so` 的 `.rodata` 有字符串 `verifyPattern`，`data.rel.ro` 中紧邻的 `dq offset` 指向实现 `sub_8120`，这是 N-API 模块注册表（`napi_property_descriptor`）的典型布局，可据此从字符串直接交叉引用到实现。
- **参数校验**：`sub_8120` 先 `napi_get_array_length` 要求长度等于 9，再循环 `napi_get_element` + `napi_get_value_int32` 把 9 个点序号读进局部数组；类型不对会抛 `Array elements must be integers`。这说明输入是「9 个 0..8 的整数序列」而非字符串，网格点的编号与顺序就是锁的图案。
- **校验算法**：读入后调用 `init_proc_(v14)` 就地变换输入数组，然后逐项与 `.data.rel.ro` 里的 `is` 比较（`v14[i] == *(DWORD*)&is + i`）。`init_proc_` 是标准 XXTEA 结构：`delta = 0x9E3779B9`、`sum` 每轮递减、`(sum>>2)&3` 选 key 下标、`MX = ((z>>5 ^ x<<2) + (x>>3 ^ z<<4)) ^ ((sum ^ x) + (key[e] ^ z))`，只是把「加密」写成对入参数组原地累加。key 为全局 `what`（4 个 DWORD：`0x0B, 0x2D, 0x0E, 0x1BF52`），比较目标是全局 `is`（9 个 DWORD）。
- **为什么能还原**：校验是「加密后比对」，算法与 key 全在二进制里且无外部熵，XXTEA 对固定长度分组可逆；因此把 `is` 当成密文做一次解密就得到期望输入数组，不需要爆破 9! 种排列。
- **小端陷阱**：`is` 在 `.data.rel.ro` 中按字节排列，必须用 `get_wide_dword()`（或按小端 `struct.unpack('<I')`）取值，直接按大端读会得到完全错误的数组。

## 触发条件

- HarmonyOS HAP 的手势/密码校验由 native `.so` 通过 N-API 导出，且未做加固。
- 校验逻辑是「输入经固定变换后与内置常量比较」的对称结构。
- 能从 `.rodata`/`.data.rel.ro` 提取 key 与比较常量。

## 利用步骤

1. 解包 HAP，反编译 `ets/modules.abc`，在 lock 页面找到 `import ... from '@normalized:...libsecret.so&.mjs'` 与 `verifyPattern(p1)` 调用，确认 `INPUT_LENGTH = 9`。
2. 提取 `libs/arm64-v8a/libsecret.so`，IDA 打开，在 Strings 窗口找 `verifyPattern`，交叉引用到 `data.rel.ro` 的描述符，再跟到实现函数。
3. 读实现：确认 `napi_get_array_length == 9`、循环取 int32、调用就地变换函数、逐项与全局数组比较。
4. 在 IDA 中定位变换函数，识别 `0x9E3779B9`、`(sum>>2)&3`、`MX` 结构，判定为 XXTEA；记录 key 全局符号 `what` 与密文全局符号 `is`。
5. 用 `get_wide_dword` 按小端提取 `is` 的 9 个 DWORD 与 `what` 的 4 个 DWORD。
6. 写 XXTEA 解密（`a[i] -= MX`，sum 从 `rounds*delta` 递减），得到 9 个点序号，按顺序拼成密码。
7. 用得到的密码解锁页面流程，继续后续关卡（本题最终 flag 是 `md5(密码 + 固定盐)`）。

## PoC

```c
/* 仅演示 XXTEA 解密核心：对 9 个 DWORD 的密文做逆运算 */
#include <stdint.h>
#include <stdio.h>

void xxtea_dec(uint32_t *a, int n, uint32_t k[4]) {
    uint32_t delta = 0x9E3779B9;
    int rounds = 6 + 52 / n;
    uint32_t sum = (uint32_t)rounds * delta;
    uint32_t y = a[0], z, e, mx;
    while (rounds--) {
        e = (sum >> 2) & 3;
        for (int i = n - 1; i > 0; i--) {
            z = a[i - 1];
            mx = ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (k[(i & 3) ^ e] ^ z));
            a[i] -= mx;
            y = a[i];
        }
        z = a[n - 1];
        mx = ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (k[e] ^ z));
        a[0] -= mx;
        y = a[0];
        sum -= delta;
    }
}

int main(void) {
    uint32_t k[4] = {0x0B, 0x2D, 0x0E, 0x1BF52};
    uint32_t a[9] = {0xeb159b69, 0x71efca1b, 0x91c9c6c6, 0x957af873, 0x0d3deab9,
                     0x27894343, 0x61d6415b, 0x1f80fed8, 0xdf62f1d9};
    xxtea_dec(a, 9, k);
    for (int i = 0; i < 9; i++) printf("%u ", a[i]);
    printf("\n");
    return 0;
}
```

```text
# 输出：1 3 4 5 0 7 2 8 6  → 手势密码 134507286
# 本题最终 flag = md5("134507286" + "Harmony5337") 的十六进制
```

## 变体与关联

- 变体：比较前可改成「输入加密」或「常量解密」，两者等价；也可把 XXTEA 换成 TEA/XTEA、或改 delta 与轮数，识别依据仍是 `0x9E3779B9` 与 MX 结构。
- 变体：校验可放在 `napi_get_value_string_utf8` 的字符串输入上，此时要按 ASCII 逐字节还原；也可加入与设备 ID 的绑定，需要动态取环境值。
- 关联：[[ctf-reverse-xxtea-custom-delta-derived-key]]、[[ctf-reverse-keygenme-xtea-self-referential-key-bruteforce]]（XXTEA 变体）、[[mobile-harmony-hap-arkts-native-sbox-affine-unicorn]]（N-API 导出 + 矩阵变换）、[[mobile-harmony-hap-abc-reverse-sourcemaps-workflow]]（HAP/ABC 解包流程）。

## 检测与防御

- 本题无服务端攻击面；对本机应用而言，本地手势锁只能防误触，不能作为安全边界。
- 检测：HAP 中出现 `@normalized:...libsecret.so&.mjs` 形式的 native 导入、native 侧 `napi_get_array_length` 后立即比较常量数组，通常是硬编码校验。
- 防御：不要把口令/图案的期望值或可逆密文放进客户端；校验应放在有防重放的服务端，或使用系统级 KeyStore 生物识别；对 native 校验函数做完整性校验与控制流混淆只能提高成本。
