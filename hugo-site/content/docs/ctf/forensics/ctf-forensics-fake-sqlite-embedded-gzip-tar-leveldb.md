---
id: ctf-forensics-fake-sqlite-embedded-gzip-tar-leveldb
title: SQLite 外壳内嵌 GZIP/TAR/LevelDB：伪装数据库的递归解包
type: scenario
domain: ctf
path: ctf/forensics
technique: fake-sqlite-embedded-gzip-tar-leveldb
tags:
- ctf
- forensics
- file-carving
- gzip
- tar
- leveldb
- sqlite
- magic-bytes
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V192
  verified_at: '2026-11-06T23:05:27+08:00'
  notes: 已对照原文与图片核对：0x60 处 1F8B08、tar、LevelDB 及填充串提取一致；已修正前100字节表述；未对附件本机执行。
url: /docs/ctf/forensics/ctf-forensics-fake-sqlite-embedded-gzip-tar-leveldb/
draft: false
kb_aliases:
- DB Mirage
- 伪装 SQLite
- 0x60 偏移 GZIP
- leveldb 取证
- 文件头欺骗
- challenge.db
---

## 一句话结论

附件 `challenge.db` 的前 0x60 字节保留了 SQLite 头，紧随其后的偏移 `0x60` 处就是 `1F 8B 08` 的 GZIP 流（覆盖了 SQLite 头部末尾的 4 字节版本字段）；从该偏移切出并解压得到 TAR，TAR 内是 LevelDB 数据目录，读取其中的值并按重复填充串的规律提取字符即可还原 flag。

## 原理

- **文件头欺骗**：多数工具（`file`、数据库取证软件、010 Editor 的模板）先读文件头判断类型。SQLite 3 的头部固定为 16 字节魔数 `SQLite format 3\0`，紧跟页大小、写/读版本、保留区、页数等字段，真实数据库的第 1 页在偏移 100（0x64）处才开始 b-tree 页头。本附件在偏移 `0x60`（96）就出现 GZIP 魔数，等于覆盖了 SQLite 头部末尾的版本字段；真正的 SQLite 文件不可能在这里出现 `1F 8B 08`，因此“数据库”只是外壳。
- **GZIP 可自定位**：GZIP 头为 `1F 8B 08`，后面是 flags、mtime、XFL、OS；从魔数处到文件尾就是一个完整 gzip member。只要在文件里搜索该三字节序列，就能把真正的载荷切出来，不需要知道题目为什么选 0x60。
- **TAR 的识别**：解压后的数据在偏移 257（0x101）处出现 `ustar`，这是 POSIX tar 头中 `magic` 字段的位置；结合 512 字节块对齐与文件名字段即可确认是 tar，而不是普通文本。
- **LevelDB 的结构**：tar 解出 `CURRENT`、`LOCK`、`LOG`、`MANIFEST-000002`、`000004.log`、`000005.ldb` 等文件，这是 LevelDB 的典型目录。LevelDB 把键值记录存在 `.ldb` SSTable 与 `.log` WAL 中，值可能被 Snappy 压缩；用 LevelDB 客户端或数据库取证工具打开目录即可遍历键值。
- **flag 的编码方式**：取出的值是一长串 `_welcome_to_sknbCTF!!!_<char>` 的重复。填充段固定为 23 字符（`_welcome_to_sknbCTF!!!_`），真正的字符紧跟在 `!!!_` 后、下一个 `_welcome` 前；按该模式做正则提取并拼接即可。

## 触发条件

- 附件扩展名/文件头看似数据库（`.db`、`.sqlite`、`SQLite format 3\0`），但用数据库工具打开报错、表为空，或页结构与头部字段矛盾。
- 十六进制查看发现非文件头区域存在 `1F 8B 08`、`PK\x03\x04`、`ustar`、`7z\xBC\xAF` 等其它容器魔数。
- 解包后出现 `CURRENT` / `MANIFEST-*` / `*.ldb` / `*.log` 组合，说明是 LevelDB/RocksDB 一类 KV 存储。
- 数据值中存在固定长度重复填充串，flag 字符被插入在固定位置。

## 利用步骤

1. 用 `file`、`xxd`、010 Editor 检查前 0x100 字节：确认 SQLite 魔数，同时检查 0x10 处的页大小是否为 2 的幂、0x1C 处的页数是否与文件大小相符；在偏移 0x60 看到 `1F 8B 08` 即可判定为伪装。
2. 以 `data.find(b"\x1f\x8b\x08")` 找到 gzip 起点，切出 `data[off:]`；用 `gzip`/`zlib` 解压（若尾部有填充，用 `zlib.decompressobj(16+zlib.MAX_WBITS)` 并忽略 `unused_data`）。
3. 检查解压结果偏移 257 是否为 `ustar`；用 `tarfile` 列出成员并解包，确认得到 LevelDB 目录。
4. 用 `plyvel`、`leveldb` 或取证工具（如 火眼）打开 LevelDB，遍历所有 key/value；若值被 Snappy 压缩而客户端不支持，先确认 LevelDB 库版本或改用能自动解压的工具。
5. 对值做正则 `_welcome_to_sknbCTF!!!_(.)`，提取每个匹配到的字符并按顺序拼接，得到 flag。
6. 若 LevelDB 无法直接打开，可先 `strings` 扫描 `.ldb`/`.log`，固定填充串通常以明文出现；必要时用 `ldb dump` 或编写 SSTable 解析器。

## PoC

切出 GZIP → TAR（未在本机对附件执行）：

```python
import io
import tarfile
import zlib

data = open("challenge.db", "rb").read()
off = data.find(b"\x1f\x8b\x08")
assert off != -1
d = zlib.decompressobj(16 + zlib.MAX_WBITS)
tar_bytes = d.decompress(data[off:])
print("tar magic:", tar_bytes[257:262])  # b'ustar'
with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
    print(tf.getnames())
    tf.extractall("out")
```

读取 LevelDB 并提取固定模式（需安装 `plyvel`，路径按实际解包结果调整）：

```python
import re
import plyvel

db = plyvel.DB("out/test.ldb", create_if_missing=False)
for key, value in db:
    chars = re.findall(rb"_welcome_to_sknbCTF!!!_(.)", value)
    if chars:
        print(key, b"".join(chars))
```

如果工具只能给出原始字节，等价的 `strings` 观察点是：`_welcome_to_sknbCTF!!!_s_welcome_to_sknbCTF!!!_k_...`，其中 `!!!_` 后的单字符依次组成 flag。

## 变体与关联

- **外壳变体**：伪造 PNG/JPEG/PDF 头，真正载荷追加在文件尾；或把 ZIP 中央目录放在文件头附近，数据在中间。
- **容器变体**：GZIP → TAR → LevelDB 只是其中一条链；也可能是 ZIP → TAR → SQLite、7z → gzip → 自定义二进制。
- **偏移变体**：载荷不一定在 0x60，可能在文件尾、PNG IDAT 之后、或按某个字段给出的偏移；统一用全文件魔数扫描（binwalk/ foremost）定位。
- **LevelDB 变体**：值可能被 Snappy 压缩或分成多个 SSTable；key 也可能承载数据；`MANIFEST`/`LOG` 可提供恢复线索。
- **关联**：[[ctf-misc-nested-zipcrypto-base32-crc32-overlap-chain]]（嵌套压缩链）、[[ctf-forensics-sqlite-freeblock-linked-list-page-xor]]（真实 SQLite 页内隐写）、[[ctf-forensics-png-invalid-chunk-type-zlib-wav-stego]]（PNG 内嵌压缩流）、[[ctf-reverse-tag-crc32-encrypted-sqlite-seed-rc6]]（加密 SQLite 资源库）。

## 检测与防御

- **取证识别**：不要只信扩展名与首 16 字节；对附件做全文件签名扫描，重点找 `1F 8B 08`、`PK\x03\x04`、`ustar`、`Rar!`、`7z\xBC\xAF`、`BZh` 等容器头，并记录所有偏移。
- **SQLite 合法性校验**：检查头部 100 字节是否完整、页大小是否为 512–65536 的 2 的幂、页数与文件大小是否一致、第 1 页 b-tree 页头是否合理；0x60 处出现别的魔数即可判定异常。
- **取证实务**：先做只读镜像/副本，记录哈希；解包时使用隔离目录，避免 tar 路径穿越覆盖原文件；对多级容器逐层记录魔数与哈希。
- **防御（真实系统）**：上传文件做内容嗅探与多层解包扫描，不能只校验扩展名或文件头；对 KV/数据库文件检查结构一致性；DLP 需能识别嵌套压缩包中的敏感数据。
- **CTF 出题思路**：用“合法头部 + 非标准偏移载荷 + 多级容器 + KV 存储 + 固定填充”组合，迫使选手放弃按文件类型直接打开，改为签名扫描与递归解包。
