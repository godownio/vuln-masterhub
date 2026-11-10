---
id: binary-pwn-heap-uaf-strdup-reuse-auth-flag
title: heap2 UAF 认证绕过：free(auth) 后 strdup 连续复用相邻 chunk 覆盖 auth 标志
type: scenario
domain: binary
path: binary/pwn/heap
technique: uaf-strdup-reuse-auth-flag
tags:
- pwn
- heap
- uaf
- strdup
- auth-bypass
- protostar
- heap2
- 32bit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V302
  verified_at: '2026-11-08T12:08:47+08:00'
  notes: 已对照原文 content.md 与 61 张图片核对：img13-40 复现 auth AAAA→login 拒绝→reset 后 auth 指针仍 0x804c008→service AAA/BBB/CCC 复用 0x804c008/0x804c018/0x804c028→auth->auth 变为 1128481568→login you have logged in already；36 个 A 单次覆盖亦一致。struct auth{name[32];int auth;} 与 sizeof(auth)=4 的指针同名胜陷阱、chunk 仅 0x10、第三次分配落 auth+32 的解释与 GDB 堆布局相符。技术原子独立、粒度合格；dedup 除自身外全部 new（tcache reclaim/结构体 data 指针等不同机制）。未验证点：未复跑 heap2 二进制，原文为 Protostar 32 位环境。
url: /docs/binary/pwn/heap/binary-pwn-heap-uaf-strdup-reuse-auth-flag/
draft: false
kb_aliases:
- heap2
- Protostar heap2
- UAF 认证绕过
- strdup 复用 chunk
- 覆盖 auth 标志
- auth/service UAF
---

## 一句话结论

在 `struct auth { char name[32]; int auth; }` 的登录程序中，`reset` 执行 `free(auth)` 但未把全局指针置空；随后 `service` 命令用 `strdup` 连续分配小 chunk，分配器复用刚释放的 auth 块及相邻块，第三次 `service` 的数据正好落在 `auth + 32`（即 `auth->auth`）上，写入非零值后 `login` 直接判定已登录，形成 UAF 导致的认证绕过。

## 原理

- **结构体与指针同名陷阱**：`struct auth *auth;` 与 `struct auth { ... }` 同名，`auth = malloc(sizeof(auth));` 实际取的是指针变量的大小（32 位下 4 字节），只分配了 8 字节的 chunk（0x10，含 header），而结构体需要 36 字节。这既造成越界写，也让 `auth->auth`（偏移 32）落在后续相邻 chunk 内。
- **free 后指针未失效**：`reset` 分支只调用 `free(auth)`，没有 `auth = NULL`；`auth` 仍指向 0x804c008 的已释放 chunk。
- **strdup 复用**：`service` 分支执行 `service = strdup(line + 7)`，对短字符串会 `malloc(strlen+1)` 申请同样落在 0x10 大小的 chunk 类。第一次 `service AAA` 复用刚释放的 0x804c008（此时 auth 与 service 指向同一地址）；第二次 `service BBB` 分配到相邻的 0x804c018；第三次 `service CCC` 分配到 0x804c028。
- **覆盖认证字段**：auth 结构体起始 0x804c008，`name[32]` 占 0x804c008–0x804c027，`auth` 字段在 0x804c028。第三次 service 的数据正好从 0x804c028 开始，写入 `CCC` 等非零值后，`if (auth->auth)` 读取到非零，打印 `you have logged in already!`。
- **等价快捷方式**：直接用一个长度 ≥36 的 service 字符串也能在单次 strdup 中覆盖到 auth+32（原文也演示了 36 个 A 的写法），因为 strdup 按字符串长度分配，越界写覆盖认证字段。
- **为什么成立**：分配器只按大小复用空闲 chunk，不区分原用途；C 代码在 free 后仍通过悬垂指针访问同一内存，是典型的 UAF + 堆重叠（overlapping chunks）利用。

## 触发条件

- 程序提供 `auth <name>`、`reset`、`service <data>`、`login` 等菜单命令，且 `reset` 后不置空 auth 指针；
- `auth` 结构体包含安全标志（如 int auth）且位于 `name` 数组之后；
- 攻击者可控制 `service` 数据长度与内容，分配器会把释放的 chunk 复用给后续同大小/相近大小的分配；
- 程序在 `login` 时只检查该标志，不校验密码或会话。

## 利用步骤

1. 输入 `auth AAAA` 分配 auth 结构体，记录 auth 指针（原文 0x804c008），此时 auth->auth 为 0。
2. 输入 `login` 确认提示 `please enter your password`（未认证）。
3. 输入 `reset` 释放 auth 结构体，观察 auth 指针仍为 0x804c008（悬垂）。
4. 输入 `service AAA`，strdup 复用 0x804c008，auth 与 service 指向同一地址（UAF 重叠）。
5. 输入 `service BBB`、`service CCC`，第三次分配落在 0x804c028，即 auth->auth 字段。
6. 输入 `login`，auth->auth 为非零，输出 `you have logged in already!`，认证绕过成功。
7. 也可直接输入 36 个以上字符的 `service AAAA...`，一次覆盖到 auth+32。

## PoC

原文交互序列（Protostar heap2）：

```text
auth AAAA
login            -> please enter your password
reset
service AAA
service BBB
service CCC
login            -> you have logged in already!
```

关键 C 代码：

```c
struct auth { char name[32]; int auth; };
struct auth *auth;
char *service;

while (1) {
    printf("[ auth = %p, service = %p ]\n", auth, service);
    if (fgets(line, sizeof(line), stdin) == NULL) break;
    if (strncmp(line, "auth ", 5) == 0) {
        auth = malloc(sizeof(auth));          // 实际只分配指针大小
        memset(auth, 0, sizeof(auth));
        if (strlen(line + 5) < 31)
            strcpy(auth->name, line + 5);
    }
    if (strncmp(line, "reset", 5) == 0) {
        free(auth);                            // 未置空
    }
    if (strncmp(line, "service", 6) == 0) {
        service = strdup(line + 7);            // 复用已释放 chunk
    }
    if (strncmp(line, "login", 5) == 0) {
        if (auth->auth) printf("you have logged in already!\n");
        else printf("please enter your password\n");
    }
}
```

## 变体与关联

- **变体**：用 `malloc` 而非 `strdup` 复用；把标志字段换成函数指针/长度字段，复用后即可控制回调或长度（UAF → 控制流劫持）；现代 glibc 有 tcache，同样会复用刚释放的 chunk，但 key 检查只防 double free，不防 UAF 重用。
- **关联**：`binary-pwn-heap-circular-dlist-delete-count1-uaf`、`binary-pwn-heap-stale-slot-create-failure-uaf` 等 UAF 卡；本卡是“UAF + 结构体相邻字段覆盖”的认证绕过最小形态。
- **边界**：需要程序在 free 后保留悬垂指针且后续分配大小匹配；若分配器不复用（如 tcache 满、不同 arena/线程）或 auth 指针被置空，则失效。

## 检测与防御

- **修复**：`free(auth); auth = NULL;`；用 `malloc(sizeof(*auth))` 而非 `sizeof(auth)`；对 `strcpy` 使用 `strncpy`/长度校验；登录标志放在独立分配的对象并做完整性校验。
- **检测**：ASan/Valgrind 会报告 heap-use-after-free；监控 free 后同一地址被重新分配并写入的堆行为；代码审计关注 `free` 后未置空、`sizeof(指针)` 误用。
- **防御**：启用堆隔离/MTE/ASan 编译；对认证对象使用不可重叠的静态存储或栈上结构；采用现代分配器与安全编码规范。
