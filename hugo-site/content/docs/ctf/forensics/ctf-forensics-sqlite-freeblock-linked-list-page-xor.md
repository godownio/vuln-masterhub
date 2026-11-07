---
id: ctf-forensics-sqlite-freeblock-linked-list-page-xor
title: SQLite Freeblock 链表隐写：sys_config 入口指针 + 大端节点 + 页号 XOR 还原隐藏 SQL
type: scenario
domain: ctf
path: ctf/forensics
technique: sqlite-freeblock-linked-list-page-xor
tags:
- ctf
- forensics
- sqlite
- freeblock
- stego
- linked-list
- xor
- database
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V162
  verified_at: '2026-11-06T14:04:53+08:00'
  notes: 已对照 91111 原文第六题与图 04-05 核对：sys_config 的 0x13B:0x4F0、>IHH 节点、XOR_PAGE_ID_BE、页大小 4096 与还原 SQL/答案均一致。PoC 未在本机复跑。
url: /docs/ctf/forensics/ctf-forensics-sqlite-freeblock-linked-list-page-xor/
draft: false
kb_aliases:
- SQLite 空闲块隐写
- Freeblock 链表
- recovery.pointer
- XOR_PAGE_ID_BE
- 页号异或
- 数据库物理空闲块
---

## 一句话结论

题目把一段 SQL 拆成自定义链表节点，藏在 SQLite 数据库文件的 Freeblock（未使用页空间）里：`sys_config` 表给出入口“页号:偏移”、节点结构 `>IHH (NextPage, NextOff, Len)` 和加密方式 `XOR_PAGE_ID_BE`；从入口开始逐节点读取 8 字节头、取 Len 字节数据、用当前物理页号的大端 4 字节循环 XOR 解密，拼接后得到完整 SQL，再执行查询即可定位目标记录。

## 原理

- **SQLite 页结构**：文件头偏移 16-17 处为页大小（本例 4096）。每个页由 b-tree 页头/单元格区/未分配区/freeblock 组成；freeblock 是页内被删除或未使用的空间，头部 4 字节记录下一个 freeblock 偏移，剩余字节可被写入任意数据而不影响数据库正常查询。
- **配置表指路**：`sys_config` 中的三行给出隐写参数：
  - `recovery.pointer: "ERR_PTR: 0000013B:04F0"`：入口物理页号 `0x13B=315`，页内偏移 `0x4F0=1264`（该偏移已跳过 freeblock 的 4 字节头，直接指向 payload）。
  - `recovery.structure: "Struct: >IHH (NextPage, NextOff, Len)"`：节点头为大端序，`NextPage` 4 字节、`NextOff` 2 字节、`Len` 2 字节。
  - `recovery.encryption: "XOR_PAGE_ID_BE"`：数据用当前物理页号的大端 4 字节表示循环 XOR。
- **链表遍历**：在 `page_id * page_size + offset` 处读 8 字节头；读完 Len 字节密文后，若 `NextPage=0 && NextOff=0` 结束，否则跳到 `NextPage * page_size + NextOff` 继续。
- **解密**：`key = struct.pack('>I', current_page)`，对 Len 字节按 `i % 4` 循环 XOR；因为密钥只与页号有关，攻击者只要知道链表入口和页大小即可离线还原，不需要数据库密码。
- **为什么隐藏**：数据位于 freeblock，不在表/索引的可见记录中；常规 `SELECT` 或 `.dump` 看不到，只有按物理页解析才能发现。`sys_config` 的“错误指针”字段本身就是线索。
- **后续**：拼接出的 SQL 是普通查询（JOIN orders/drivers，按路线、重量、电话后缀、处理码筛选）；执行后得到 container_id 与 license_plate。

## 触发条件

- 提供 SQLite 数据库文件，且存在自定义配置表（如 `sys_config`）记录 recovery 指针/结构/加密方式。
- 数据库页中存在 freeblock，payload 未被后续写入覆盖。
- 已知页大小与入口页号/偏移；节点结构足够明确（大端/小端、字段宽度）。
- 加密为简单的页号相关 XOR/固定 key，而非强加密。

## 利用步骤

1. 用 `sqlite3` 连接数据库，查询配置表：`SELECT * FROM sys_config;`，记录 pointer、structure、encryption。
2. 从文件头偏移 16 读取 2 字节大端页大小（常见 4096）；解析入口 `页号:偏移`。
3. 在 `page * page_size + offset` 读取 8 字节节点头：`>I` NextPage、`>H` NextOff、`>H` Len。
4. 读取 Len 字节密文；用 `struct.pack('>I', current_page)` 循环 XOR 解密；追加到结果。
5. 若 NextPage/NextOff 非 0，跳到下一节点重复；直到 0/0。
6. 拼接得到 SQL 脚本，在数据库上执行，读取目标 `container_id`/`license_plate` 等字段。
7. 若解密乱码，检查页号字节序（BE/LE）、是否跳过 freeblock 4 字节头、页大小与偏移是否正确。

## PoC

```python
import struct

DB = 'challenge.db'
PAGE_SIZE_OFF = 16
ENTRY_PAGE = 0x13B
ENTRY_OFF = 0x4F0

data = open(DB, 'rb').read()
page_size = struct.unpack('>H', data[PAGE_SIZE_OFF:PAGE_SIZE_OFF + 2])[0]
print('page_size =', page_size)

def xor_page(blob, page_id):
    key = struct.pack('>I', page_id)
    return bytes(b ^ key[i % 4] for i, b in enumerate(blob))

out = bytearray()
page, off = ENTRY_PAGE, ENTRY_OFF
while True:
    base = page * page_size + off
    next_page, next_off, length = struct.unpack('>IHH', data[base:base + 8])
    enc = data[base + 8:base + 8 + length]
    out += xor_page(enc, page)
    print(f'page={page} off={off} len={length} -> next={next_page}:{next_off}')
    if next_page == 0 and next_off == 0:
        break
    page, off = next_page, next_off

sql = out.decode('utf-8', errors='replace')
print(sql)
```

原文还原出的 SQL 形如：

```sql
SELECT t1.container_id, t2.license_plate
FROM orders t1
JOIN drivers t2 ON t1.driver_id = t2.driver_id
WHERE t1.route_path LIKE '%深圳转运中心%'
  AND t1.weight_kg BETWEEN 45.50 AND 45.60
  AND t2.phone LIKE '%9527'
  AND t1.handling_code = 'LIDAR_QC_HOLD';
```

执行后得到 `container_id=CN2888991777`、`license_plate=粤B-52816`。

## 变体与关联

- **结构变体**：节点头可能用小端、字段宽度不同、带校验和/长度异或；入口可能在 freelist trunk、unallocated 区、WAL 或索引页。
- **加密变体**：页号 XOR 的字节序/重复方式、页号加减偏移、页号与固定 key 组合、按节点索引变化。
- **隐藏位置变体**：SQLite freeblock、`sqlite_sequence`、未使用单元格、overflow page、WAL/SHM；也常见于其他数据库的未分配页。
- **关联卡片**：[[ctf-forensics-ext4-image-unallocated-strings-residual]]（未分配空间残留）、[[ctf-forensics-partial-ewf-ntfs-openssl-memory-decrypt]]（删除/未分配数据恢复）、[[ctf-reverse-tag-crc32-encrypted-sqlite-seed-rc6]]（SQLite 加密逆向）。
- **边界**：若 freeblock 被后续插入/更新覆盖，payload 可能损坏；页大小/入口偏移错误会读到 b-tree 内容；强加密或 key 不在本地时无法离线还原。

## 检测与防御

- **CTF 识别**：数据库能正常打开但题目要求“检查 sys_config/物理空闲块”，配置表中出现 `ERR_PTR`、`Struct:`、`XOR_PAGE_ID` 等非常规字段。
- **取证**：保留原始数据库文件与哈希；按页解析而非只做 SQL 查询；记录每个节点的页号、偏移、长度与解密结果，便于验证。
- **防御（数据隐藏视角）**：不要把秘密放在数据库未分配空间并依赖“不可见”；freeblock 可能被 VACUUM/写入复用，也可能被取证工具提取。
- **安全**：对数据库文件做完整性校验/加密；敏感数据不要以自定义链表形式分散存放；备份与日志同样需要保护。
