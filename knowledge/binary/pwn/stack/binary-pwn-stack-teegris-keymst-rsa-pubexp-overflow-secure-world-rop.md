---
id: binary-pwn-stack-teegris-keymst-rsa-pubexp-overflow-secure-world-rop
title: TEEgris KEYMST 可信小程序 RSA 公钥指数栈溢出：pub_exp_size 可控泄到 0x1f8 字节，qiling 构造输入后在安全世界 ROP
type: scenario
domain: binary
path: binary/pwn/stack
technique: teegris-keymst-rsa-pubexp-memcpy-stack-overflow-secure-world-rop
aliases:
- KEYMST 栈溢出
- TrustZone TA 栈溢出
- hal_rsa_key_get_pub_exp
- pub_exp_size 溢出
- 安全世界 ROP
- TEEgris 漏洞利用
- qiling 构造 TEE 输入
tags:
- pwn
- stack
- tee
- teegris
- trustzone
- arm
- rop
- qiling
- android
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: Android P（KEYMST 仅存在于 Android P 固件）
verification:
  verified_by: verifier-V545
  verified_at: '2026-11-11T20:51:13+08:00'
  notes: 已对照原文核对：hal_rsa_key_get_pub_exp的memcpy(&v4,content+pub_exp_offset,pub_exp_size)、校验<512字节、0x200-8=0x1f8溢出、checksec(ARM32/No RELRO/No canary/NX/No PIE 0x10000)、87856字节覆盖率构造输入、mmap(0xdead000,0x8000,RW)、[KEYMST:thumb]0x1975c ldm.w、TEE约束（无mprotect/RX、socket PROT_EXEC失败、TEES_*对KEYMST返回EPERM）均一致。affected_versions=Android P与原文“KEYMST只存在于Android P固件、更新版本不受影响”一致，已用set-versions按原文再确认。dedup与STST卡为同设备两阶段链式利用但不同组件/漏洞，非同一条卡。未实测（无受影响的真机）。
---

## 一句话结论

TEEgris 的密钥管理可信小程序 KEYMST 在导入 PKCS8 RSA 私钥时，把攻击者控制的公开指数长度 `pub_exp_size` 直接传给 `memcpy(&v4, content + pub_exp_offset, pub_exp_size)`——校验只要求指数小于 512 字节，因此最多可溢出 `0x200-8 = 0x1f8` 字节到栈；该 TA 无 canary、无 PIE、No RELRO，溢出可覆盖返回地址。由于生产设备无法调试安全世界，作者用 qiling 搭 TEEgris 模拟器、以覆盖率反馈构造出合法请求，再用 0x1f8 字节的引导 ROP 链 mmap 固定新栈、复制嵌入的第二段 ROP 并经 Thumb2 `ldm.w` gadget 切换，最终在安全世界执行任意代码。

## 原理

- **数据流**：`TA_InvokeCommandEntryPoint` → `tz_process_command`（校验 paramTypes）→ `km_import_key`（解析 PKCS8 私钥）→ `km_rsa_key_get_pub_exp` → `hal_rsa_key_get_pub_exp`：
  ```c
  __int64 hal_rsa_key_get_pub_exp(hal_rsa_key *a1) {
    size_t pub_exp_size = a1->pub_exp_size;
    char *v2 = (char *)&a1->content + a1->pub_exp_offset;
    __int64 v4 = 0LL;
    memcpy(&v4, v2, pub_exp_size);   // pub_exp_size 来自普通世界输入
    return v4;
  }
  ```
  `v4` 是栈上 8 字节局部变量，`pub_exp_size` 无上限地用于 memcpy；密钥实现只验证“公开指数 < 512 字节”，于是可达 0x200 字节，溢出 0x200-8=0x1f8。
- **缓解缺失**：`pwn checksec` 显示 ARM32、No RELRO、No canary、NX enabled、No PIE(0x10000)——栈溢出可直接改写返回地址，库地址固定，gadget 可直接引用。
- **输入构造**：请求要穿过 paramTypes 校验、PKCS8 解析、标签表解析等多层校验，且生产设备没有安全世界调试器，无法观察走到了哪一步。作者用 qiling 模拟 TEEgris（见关联卡），进入消息循环后映射输入并调用 `TA_InvokeCommandEntryPoint`，用 drcov 生成覆盖率给 IDA/lighthouse，迭代构造出 87856 字节的输入——其中只有 PKCS8 私钥与“标签表”区域被读取/校验，其余大部分空间可自由放置利用数据。
- **ROP 两段式**：首段只有 0x1f8 字节，先保存寄存器到 bss，用 `mmap` 在固定地址 `0xdead000` 映射 0x8000 字节 RW 作为新栈，把共享输入缓冲区的大部分复制过去；随后用 Thumb2 `ldm.w` gadget（`[KEYMST:thumb] 0x1975c`）把嵌入的第二段 ROP 载入寄存器并切换 sp，链上分别布置新寄存器值（0x100-0x200）、`sp = 0xdead000+0x200`（0x200-0x6000）与数据区（0x6000-0x8000）。
- **安全世界约束**：进入 TA 后的探索表明——文件不能以写模式打开；匿名内存无法通过 mprotect 变 RX；socket mmap 设 PROT_EXEC 失败；`TEES_ExecuteCustomHandler`/`TEES_RegisterCustomHandler` 对 KEYMST 返回 EPERM。但可以把已有文件以固定地址只读 RX 映射，从而引入 `libteesock.so` 等库扩充 gadget 集。

## 触发条件

- 目标设备为搭载 TEEgris 的三星 Exynos 设备，且 KEYMST TA 版本受影响（Android P 固件；更新版本已修复）。
- 攻击者已能在普通世界以足够权限向 TEE 发送请求（如内核失陷后经 tzdaemon/tz_wormhole，或恶意应用利用可达的 TEE 客户端路径）。
- KEYMST 的 PKCS8 导入路径可达，`pub_exp_size`/`pub_exp_offset` 受输入控制。
- 仅用于授权测试与自有设备研究。

## 利用步骤

1. 从设备/固件提取 KEYMST TA（见关联卡），checksec 确认为 ARM32、No canary、No PIE、No RELRO，定位 `hal_rsa_key_get_pub_exp`。
2. 用 qiling 搭 TEEgris 模拟环境，从 `TA_InvokeCommandEntryPoint` 起步，映射输入缓冲区并记录覆盖率；迭代构造能通过 paramTypes/PKCS8/标签表校验的请求，确认 `memcpy` 长度可控。
3. 计算溢出偏移（v4 到返回地址），确认最多 0x1f8 字节可用；在输入缓冲区剩余空间布置第二段 ROP 与数据。
4. 构造首段链：保存寄存器到 bss → `mmap(0xdead000, 0x8000, RW)` → 复制输入缓冲区到新栈 → `ldm.w` gadget 切 sp 到 `0xdead000+0x200`。
5. 在第二段链中调用安全世界系统调用做信息收集/持久化；需要新 gadget 时把已有 .so 以固定地址 RX 映射进来。
6. 在模拟器验证链的每一步与最终效果，再通过普通世界通道向真实设备提交请求；记录影响与版本边界。

## PoC

```c
// 漏洞函数（伪代码，来自 KEYMST TA 反编译）
__int64 hal_rsa_key_get_pub_exp(hal_rsa_key *a1) {
  size_t pub_exp_size = a1->pub_exp_size;          // 普通世界可控
  char *v2 = (char *)&a1->content + a1->pub_exp_offset;
  __int64 v4 = 0LL;
  memcpy(&v4, v2, pub_exp_size);                   // 最多 0x200 字节 -> 溢出 0x1f8
  return v4;
}
```

```text
# 输入缓冲区布局（约 87856 字节，黄色区域为被校验读取的部分）
[PKCS8 RSA private key][label table][...未使用空间: 存放 ROP 链与数据...]

# 首段 ROP（0x1f8 字节）
save regs -> bss
mmap(0xdead000, 0x8000, PROT_READ|PROT_WRITE)
memcpy(0xdead000, input_buf, len)
ldm.w  ...  ; [KEYMST:thumb] 0x1975c，切 sp 到 0xdead000+0x200

# 第二段（嵌入输入缓冲区）
[0x100-0x200] 新寄存器值
[0x200-0x6000] sp = 0xdead000 + 0x200
[0x6000-0x8000] 数据（syscall 输入/输出）
```

```text
# checksec
Arch: arm-32-little | RELRO: No RELRO | Stack: No canary found | NX: enabled | PIE: No PIE (0x10000)
```

## 变体与关联

- 变体：不同 TA 的入口/命令校验不同，但“外部可控长度 memcpy 到栈 + 无 canary + 无 PIE”的模式可复用；输入构造都可用覆盖率反馈提速。
- 变体：首段空间更小时，可只用 `mmap` + 一次 `ldm` 或栈迁移 gadget；也可把下一段放在共享缓冲区的固定映射地址（若映射地址可预测）。
- 变体：安全内核禁用 mprotect 时，用“已有文件固定地址 RX 映射”扩充 gadget（如 libteesock.so 的间接分支）。
- 关联：[[code-analysis-reverse-firmware-qiling-teegris-syscall-emulation]]（构造输入的模拟器）、[[code-analysis-reverse-firmware-samsung-teegris-ta-extraction]]（提取 KEYMST）、[[binary-pwn-rop-thumb2-ldm-gadget-tool-blindspot]]（链中使用的 Thumb2 ldm gadget 与工具盲区）、[[binary-pwn-format-string-teegris-stst-driver-arbitrary-rw-custom-printf-rce]]（同一设备链式利用的第二个漏洞）。

## 检测与防御

- 检测：TA 侧记录异常大的 RSA 公钥指数（>64 位）导入请求；监控 TA 崩溃/异常返回；设备完整性检测（root/内核失陷）可降低 TEE 被触达的概率。
- 防御：TA 编译开启 canary/PIE/RELRO；对 `pub_exp_size` 做严格上限校验（RSA 公钥指数通常 ≤ 8 字节）并检查 `offset+size` 边界；用带长度检查的拷贝函数；TA 输入解析前先做整体结构验证；及时更新固件（Android P 之后已修复）。
- 说明：本文是三星 TEEgris KEYMST TA 的栈溢出到安全世界代码执行场景，severity high、confidence high（三星确认影响 Android P 固件）；仅用于授权测试与自有设备研究。
