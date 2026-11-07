---
id: ctf-forensics-http-range-fragment-reassembly-sqlcipher
title: HTTP Range 分片重组取证：Content-Range 回填 + MD5 校验 + 邮件线索恢复 SQLCipher 口令
type: scenario
domain: ctf
path: ctf/forensics
technique: http-range-fragment-reassembly-sqlcipher
aliases:
- HTTP Range 重组
- Content-Range 回填
- 206 Partial Content
- SQLCipher 口令恢复
- eml 线索
- users.db 恢复
tags:
- ctf
- forensics
- pcap
- http-range
- reassembly
- sqlcipher
- md5
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:28:32+08:00'
  notes: 已对照原文 数据恢复与审计 1/2 核对：Range/206/Content-Range 回填、851968 字节 users.db、MD5 校验、email.eml base64 线索、liwei1993 SQLCipher 口令均一致；已修正 PoC 中 total 在赋值前使用的问题（改为先从首个 Content-Range 解析 total）；未实际运行。
---

## 一句话结论

pcap 中同一文件被 `Range: bytes=a-b` 分成大量 206 响应；按每个 `Content-Range` 的起止偏移把响应体写回目标文件对应位置，拼出完整 `users.db` 并 MD5 校验；同法重组 `email.eml`，base64 正文给出“姓名小写全拼 + 4 字符”的 SQLCipher 口令线索。

## 原理

- **206 响应体是原文件的字节切片**：`Content-Range: bytes 717591-719468/851968` 表示这段 body 属于原文件偏移 717591–719468；把 body 写到该偏移即可无损重组，无需按请求顺序。
- **HEAD/首个响应给总大小**：`Content-Range: bytes 0-851967/851968` 或 `Content-Length` 给出文件总长度，用于预分配与完整性检查。
- **MD5 校验**：重组后与题目给定/邮件中的 MD5 对比，可确认没有缺片/重叠错误。
- **邮件线索**：`.eml` 正文常为 base64/quoted-printable；解码后得到“密码是姓名小写全拼 + 四个字符”的提示，结合收件人姓名猜出 `liwei1993`，用 SQLCipher `PRAGMA key` 验证。
- **SQLCipher 验证**：口令正确时 `SELECT name FROM sqlite_master` 能正常返回表名；错误时打开失败/报错。

## 触发条件

- pcap 中有 `Range` 请求与 `206 Partial Content` 响应，`Content-Range` 完整。
- 目标文件可识别（SQLite 头 `SQLite format 3`、eml 头）。
- 题目提供 MD5 或可校验的已知结构。
- SQLCipher 口令线索可从邮件/日志/元数据恢复。

## 利用步骤

1. `tshark` 过滤 `http.request.uri contains "/download/"` 与对应响应，导出 `Content-Range`、响应体。
2. 解析每个 `Content-Range: bytes start-end/total`，按 `start` 把 body 写入预分配的 `bytearray(total)`。
3. 检查所有字节是否被覆盖（可用覆盖位图），计算 MD5 与题目值对比。
4. 对 `/download/email.eml` 重复同样流程，重组邮件。
5. 解码邮件正文（base64/quoted-printable），提取口令格式与姓名线索。
6. 用 `sqlcipher`/`pysqlcipher3` 打开 DB，`PRAGMA key='<候选>'`，执行 `SELECT name FROM sqlite_master` 验证。

## PoC

```python
import re
from hashlib import md5

# 先从 HEAD/首个 206 的 Content-Range 取总大小
m0 = re.search(rb"Content-Range:\s*bytes\s+\d+-\d+/(\d+)", fragments[0][0], re.I)
total = int(m0.group(1))
buf = bytearray(total)
covered = bytearray(total)
for headers, body in fragments:              # 从 pcap 提取的 206 响应
    m = re.search(rb"Content-Range:\s*bytes\s+(\d+)-(\d+)/(\d+)", headers, re.I)
    start, end, _ = map(int, m.groups())
    buf[start:end+1] = body[:end-start+1]
    covered[start:end+1] = b"\x01" * (end-start+1)

assert all(covered), "missing fragments"
open("users_reconstructed.db", "wb").write(buf)
print(md5(buf).hexdigest())
```

```sql
-- sqlcipher users_reconstructed.db
PRAGMA key = 'liwei1993';
SELECT name FROM sqlite_master WHERE type='table';
```

## 变体与关联

- **分片变体**：重叠/乱序/重复分片、gzip `Content-Encoding`、chunked、多文件并发；需要先解压再按偏移写。
- **协议变体**：FTP RETR、SMB、rsync、HTTP/2 DATA 帧；也可用 `tcpflow`/`NetworkMiner` 先落盘。
- **口令变体**：邮件正文、附件、聊天记录、配置文件、键盘记录；SQLCipher 口令可能是姓名+生日/手机号后四位/年份。
- **关联卡片**：[[ctf-forensics-fat16-deleted-noncontiguous-extent-recovery]]（非连续簇恢复）、[[mobile-android-sqlcipher-static-key-derivation]]（SQLCipher 静态密钥）、[[defense-forensics-sqlcipher-im-db-memory-key-extraction]]（内存取 key）。
- **边界**：若缺少分片或 `Content-Range` 被截断，重组文件不完整；SQLCipher 版本/参数（KDF 迭代、页大小）不同可能影响打开。

## 检测与防御

- **CTF/审计验证**：重组后先看文件头（SQLite/eml），再 MD5 对比；SQLCipher 用 `sqlite_master` 验证口令。
- **防御**：下载接口做鉴权与审计；避免把完整 DB 分片暴露给未授权用户；SQLCipher 口令不要由姓名/生日等可猜测信息派生，使用高熵随机口令并加 KDF。
- **检测信号**：短时间内大量 Range 请求覆盖同一文件；206 响应总字节数接近文件大小；邮件中出现口令提示。
