---
id: web-java-deserialization-mapdb-linked-record-pointer-rewrite-deser-rce
title: mapdb linked record 指针改写：8 字节目录穿越写把反序列化重定向到分段 Payload
type: scenario
domain: web
path: web/java/deserialization
technique: mapdb-linked-record-pointer-rewrite-deserialization-rce
tags:
- java
- deserialization
- mapdb
- linked-record
- file-write
- directory-traversal
- rce
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T10:15:06+08:00'
  notes: 已对照 staircase 段核对：/files/modify 8 字节带前后缀写、mapdb tempFileDB /proc/self/fd、indexVal size<<48|offset|linked|parity、linkedRecordGet 拼接、Jackson/TemplatesImpl 链均吻合；PoC 未执行
url: /docs/web/java/deserialization/web-java-deserialization-mapdb-linked-record-pointer-rewrite-deser-rce/
draft: false
kb_aliases:
- mapdb 反序列化
- linked record
- StoreWAL get 指针
- 8 字节任意文件写
- /proc/self/fd 临时数据库
- staircase
---

## 一句话结论

应用存在“带前后缀的 8 字节任意文件写”并使用了 mapdb 临时数据库时，可以改写 mapdb 记录的指针（`size<<48 | offset | linked/parity`），把 `StoreWAL#get` 的二级/三级读取重定向到攻击者通过 `icon` 上传的 linked record；linked record 把多个小段串成约 3KB 的连续数据，绕过 324 字节上传限制，最终触发 Jackson/TemplatesImpl 反序列化 RCE。

## 原理

- **mapdb 临时文件**：`DBMaker.tempFileDB()` 创建临时文件后立即 `delete()`，但保持 fd 打开；因此可通过 `/proc/self/fd/<N>` 访问数据库文件。mapdb 用 Java 原生序列化持久化 key/value。
- **记录指针编码**：`StoreWAL#get(recid)` 读取 `indexVal`，高 16 位是记录 size，低 48 位是文件 offset，另有 linked 标志（bit 0x8）与奇偶校验位。若 `indexValFlagLinked` 为真，则进入 `linkedRecordGet`，按链表逐段读取并拼接。
- **多级引用**：`HTreeMap#getprotected` 先 `indexTree.get(index)` 得到 leaf recid，再 `leafGet(store, recid)`，最后 `valueUnwrap(segment, leaf[i+1])`；每一步都走 `StoreWAL#get` 反序列化。这些“指针”在文件中都是 8 字节，攻击者可通过文件写修改，把读取重定向到任意 offset/size。
- **linked record 拼接**：`linkedRecordGet` 从 `indexValue` 指向的 item 开始，读取 size（减去 8 字节 next 指针）并追加到缓冲区；若当前 item 是 linked，则从 item 开头 8 字节读出 next pointer 继续。最后返回拼接后的字节并反序列化。利用该特性可把多段小 payload 串成完整 gadget。
- **覆盖特性**：`updateProtected` 对新值做 16 字节对齐；若对齐后大小与旧值相同则复用原 offset，否则 `allocateData` 分配新位置且不删除旧数据。写入长度和顺序固定时新地址可预测，因此可先上传多段，再计算每个 item 的 offset。
- **8 字节写原语**：`/files/modify` 路由存在目录穿越，可修改任意文件内容，但一次只能改 8 字节，且会带 `<start>` 前缀和 `<end>` 后缀；选择 offset 使 8 字节落在指针字段上即可精确改指针（前后缀落在无关区域）。
- **最终 gadget**：上传的 `icon` 是序列化对象；通过 linked record 拼接出超过 324 字节的 Jackson `POJONode`/`TemplatesImpl` 链，触发时执行字节码。

## 触发条件

- 应用使用 mapdb（`StoreWAL`/`HTreeMap`）持久化缓存，数据库文件可通过 `/proc/self/fd/N` 访问。
- 存在可写任意文件、一次 8 字节且带固定前后缀的接口；攻击者能控制写入 offset。
- 应用允许上传 `icon`（≤324 字节）并把它作为 mapdb 的 value 存储；后续读取 `icon` 时会反序列化。
- classpath 存在可用的反序列化 gadget（示例 Jackson + TemplatesImpl + Spring AOP/JDK 链），目标 JDK 版本允许。
- 攻击者能在本地复现相同 mapdb 写入顺序，计算各 item 的固定 offset。

## 利用步骤

1. **探测路径/文件**：确认 `/files/modify` 的目录穿越与 8 字节限制；通过 `/proc/self/fd/N` 枚举/猜测 mapdb 文件 fd（示例 9/11）。
2. **生成 gadget**：用 Jackson `POJONode` + `TemplatesImpl`（或其它可用链）生成序列化 payload，长度约 2.7KB；准备执行 `cat /f* > /app/uploads/test.txt`。
3. **分段上传**：按 `18*18-8-5-8` 递减的 item 大小拆分 payload；每次上传 `icon`（内容为 `"aaaaa" + next_pointer + chunk`），让 mapdb 分配连续/可预测的 offset；最后一个 item 不带 next 指针。
4. **计算指针**：按 `size<<48 | offset | linked(8) | parity` 生成每个 item 的 8 字节 next pointer；parity 用 `DataIO.parity` 规则计算（bit_count 校验）。
5. **改指针**：用 `/files/modify` 把 mapdb 中第二步/第三步的 leaf/value 指针改成第一段 item 的 offset/size；前后缀 `<start>/<end>` 落在指针外的字节可忽略。
6. **触发反序列化**：请求“获取文件图标”等会读取 `icon` 的功能，mapdb 按伪造指针走 linked record，拼接出完整 payload 并反序列化，执行命令。
7. **回显**：命令把 flag 写到 `/app/uploads/test.txt`，通过下载/读取功能取回。

## PoC

```python
def calc_pointer(offset, size, is_pointer):
    p = (size << 48) | offset | (8 if is_pointer else 0)
    p |= ((bin(p).count("1") + 1) % 8) & 0x7   # mapdb parity
    return p.to_bytes(8, "big")

def gen_payload(payload):
    max_len = 18 * 18 - 8 - 5 - 8
    chunks = []
    while payload:
        chunks.append(payload[:max_len]); payload = payload[max_len:]
        max_len -= 16
    return chunks

# 上传分段：aaaaa + next_pointer + chunk
for i in range(len(chunks) - 1):
    nxt = calc_pointer(offsets[i+1], len(chunks[i+1]) + 8, True)
    send(b"aaaaa" + nxt + chunks[i])
send(b"aaaaa" + chunks[-1])

# 改 mapdb 指针（示例 fd 9/11）
fix(bytes([0x83,0x84,0xE9,0xE3,0xEF,0xEE,0x94,0x80]), 0x100300 - 7, "/proc/self/fd/9")
fix(calc_first_pointer(offsets[0], len(chunks[0]) + 8), 0x8108 - 7, "/proc/self/fd/9")
```

具体 offset、fd、parity 与 `_cache` 键依目标环境而定；原文在 Docker 环境先本地写入一遍确定固定地址。本卡不执行 PoC。

## 变体与关联

- **其它嵌入式数据库**：H2、SQLite、LevelDB 等的文件格式/指针也可被任意写篡改，导致反序列化/记录重定向；关键是数据库文件可经 `/proc/self/fd` 访问且指针未校验。
- **其它任意写原语**：8 字节写、OOB 写、日志注入写都可替代 `/files/modify`；linked record 只是绕过大小限制的手段。
- **gadget 选择**：Jackson/TemplatesImpl、Spring AOP、JDK `EventListenerList` 等；按目标 classpath 选择。
- **关联**：[[web-java-deser-fury-usingtostring-datastore-ioUtils-secondary-deser]]（二次反序列化桥）、[[web-java-deserialization-causeway-viewmodel-bookmark-memento-rce]]（文件/URL 反序列化）、[[web-java-classloader-charsets-jar-bootstrap-overwrite-accept-gbk-rce]]（文件写升级 RCE）。
- **边界**：需要 mapdb 临时文件可访问、8 字节写可控 offset、上传 value 会反序列化；若 mapdb 记录有校验/加密、文件 fd 不可达、或反序列化过滤器拦截 gadget，利用失败。

## 检测与防御

- **修复穿越**：`/files/modify` 对路径做 canonical 校验，限制在允许目录；禁止通过 `/proc/self/fd` 访问内部文件；一次写入长度/前后缀不应可控到任意 offset。
- **数据库完整性**：mapdb 记录指针加校验/加密；不要把内部数据库文件暴露在可写路径；临时文件使用 `O_TMPFILE` 且不保留可访问路径。
- **反序列化防护**：对 mapdb value 使用安全序列化/白名单，禁用原生 Java 序列化；JEP 290 过滤器拦截 TemplatesImpl/Jackson gadget。
- **检测**：`/files/modify` 请求中出现 `/proc/self/fd`、异常 offset/8 字节写；mapdb 文件指针区域被修改；应用读取 `icon` 后出现反序列化异常/子进程；`/app/uploads` 出现异常文件。
- **响应**：隔离实例、恢复数据库、轮换凭据、审计上传与文件修改日志。
