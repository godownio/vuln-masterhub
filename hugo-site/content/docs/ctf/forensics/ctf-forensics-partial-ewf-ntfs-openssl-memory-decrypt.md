---
id: ctf-forensics-partial-ewf-ntfs-openssl-memory-decrypt
title: 部分 EWF 镜像解析 + NTFS 删除文件/git 对象恢复 + OpenSSL aes-256-cbc 解密核心记忆
type: scenario
domain: ctf
path: ctf/forensics
technique: partial-ewf-ntfs-deleted-recovery-openssl
tags:
- ctf
- forensics
- ewf
- e01
- ntfs
- partial-image
- git-object
- deleted-file
- openssl
- pbkdf2
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-06T02:17:14+08:00'
  notes: V118 指出的 PoC/代码错误已修正并重新 verify
url: /docs/ctf/forensics/ctf-forensics-partial-ewf-ntfs-openssl-memory-decrypt/
draft: false
kb_aliases:
- Lost_Memory
- 部分 EWF 镜像
- E01 分块表解析
- NTFS 删除文件恢复
- git 对象碎片
- OpenSSL aes-256-cbc pbkdf2
---

## 一句话结论

题目给出约 21GB 压缩包，解压出约 64GB 的 EWF 磁盘镜像；解压到 30.96GB 时宿主磁盘写回限流，完整镜像不可用，libewf 在约 27.5GB 处报 I/O 错误无法挂载。用自定义的部分 EWF 解析器直接读取可读前缀（约 30.6GB 介质），按 GPT/NTFS 定位五块被清空的记忆碎片：删除的临时网页文件、项目仓库 git 对象、崩溃备份日志（回收站副本一字节损坏）、两处数据库页已被覆盖（由整体短语反推并解密验证）；按编号 1 到 5 拼接得到 `after_all_this_time_always_YA20180507`，用带盐 OpenSSL aes-256-cbc + pbkdf2 解密核心记忆转储，得到 flag。

## 原理

- **EWF v1 结构**：镜像为单段未压缩 EWF（FTK Imager 风格），由 section descriptor 链组成，descriptor 为 `<16sQQ40sI>`（type、next_offset、size、padding、checksum），长度 76 字节；`sectors` section 后面跟 `table` section，table 头包含 chunk 数、base offset，随后是每个 chunk 相对 base 的 4 字节 LE 偏移；每个 chunk 是 32KiB 原始数据 + 4 字节 Adler32。
- **部分镜像可读**：即使文件不完整，只要 descriptor 链、table、目标 chunk 落在已写入前缀内，就能按 chunk 索引顺序计算介质偏移并读取；不完整的 chunk 直接跳过。`libewf` 挂载要求完整结构，因此在 27.5GB 处失败，而自定义解析器可读到 30.6GB。
- **GPT/NTFS**：介质为 60GB，GPT 分区包含 EFI 系统分区、微软保留分区、59.29GB 的 NTFS 分区与恢复分区。NTFS 中可定位删除文件记录、`$MFT`、目录索引与数据簇；删除的临时网页文件、git 对象、崩溃备份日志都留有可用副本。
- **五块碎片**：
  1. 第一块来自被删除的临时网页文件；
  2. 第二块来自项目仓库的 git 对象，内容带碎片标记，同一仓库的原始对象还留有核心密钥片段；
  3. 第四块来自崩溃备份日志，回收站副本显示有一字节损坏；
  4. 第三块与第五块没有独立副本，相关数据库页已被覆盖，最终由整体短语反推，并由解密成功反向验证。
- **编号与密钥**：芯片硬件编号在外壳上蚀刻为分段形式 `YA_20180507`，在固件中为连续编号 `YA20180507`；五块碎片按编号首尾相接（顺序 1 到 5，不是发现顺序），得到 `after_all_this_time_always_YA20180507`。
- **解密**：核心记忆转储使用带盐 OpenSSL `aes-256-cbc` + `pbkdf2`；用上述口令解密，明文即 AI 恢复后的核心记忆，结尾给出 flag。

## 触发条件

- 提供部分写入/损坏的 EWF/E01 镜像，完整挂载失败但前缀可读。
- 镜像包含 GPT/NTFS 分区，删除文件、git 对象、日志/数据库页等碎片可恢复。
- 碎片有编号/顺序线索，且能拼成可验证的口令/密钥。
- 加密容器使用常见 OpenSSL 格式（Salted__ 头、aes-256-cbc、pbkdf2），可用口令离线解密。

## 利用步骤

1. 解压压缩包，记录解压中断位置与镜像实际大小；用 `libewf`/`ewfmount` 尝试挂载，确认失败点。
2. 解析 EWF descriptor 链，定位 `sectors`/`table` section，建立 chunk 索引 → 文件偏移映射，校验 Adler32；只读取已写入的 chunk。
3. 解析 GPT 分区表，定位 NTFS 分区；用 NTFS 解析器遍历 `$MFT`、目录索引、删除记录与数据簇。
4. 在 NTFS 中恢复五块碎片：删除的临时网页文件、git 对象、崩溃备份日志、数据库页残留；记录编号与损坏情况。
5. 按编号 1..5 拼接碎片，结合外壳/固件中的硬件编号，得到 `after_all_this_time_always_YA20180507`。
6. 用 `openssl enc -d -aes-256-cbc -pbkdf2 -in core.bin -pass pass:<口令>` 解密，读取明文 flag。

## PoC

部分 EWF 解析核心：

```python
import struct, zlib

DESC = "<16sQQ40sI"
DESC_LEN = struct.calcsize(DESC)  # 76
CHUNK = 32768

class PartialEWF:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.size = len(self.f.read())
        self.chunks = []  # (media_off, file_off)
        self._parse()

    def _read_at(self, off, n):
        self.f.seek(off)
        return self.f.read(n)

    def _parse(self):
        off, sect = 0x0d, []
        while off + DESC_LEN <= self.size:
            typ, nxt, ssz, pad, chk = struct.unpack(DESC, self._read_at(off, DESC_LEN))
            t = typ.rstrip(b"\x00").decode("latin1")
            sect.append((off, t, nxt, ssz))
            if t in ("done", "next") or nxt <= off or nxt == 0xffffffffffffffff:
                break
            off = nxt
        for idx, (off, t, nxt, ssz) in enumerate(sect):
            if t != "sectors":
                continue
            if off + ssz > self.size:
                break
            if idx + 1 >= len(sect) or sect[idx + 1][0] != nxt or sect[idx + 1][1] != "table":
                break
            toff, _, _, tsz = sect[idx + 1]
            if toff + tsz > self.size:
                break
            data_off, data_len = toff + DESC_LEN, tsz - DESC_LEN
            hdr = self._read_at(data_off, 24)
            count = struct.unpack("<I", hdr[0:4])[0]
            base = struct.unpack("<Q", hdr[8:16])[0]
            raw = self._read_at(data_off + 24, 4 * count)
            offs = struct.unpack("<%dI" % count, raw)
            for rel in offs:
                fo = base + rel
                if fo + CHUNK + 4 <= self.size:
                    self.chunks.append((len(self.chunks) * CHUNK, fo))

    def read(self, off, length):
        out, pos = bytearray(), off
        while length > 0:
            ci, co = pos // CHUNK, pos % CHUNK
            if ci >= len(self.chunks):
                break
            _, foff = self.chunks[ci]
            n = min(CHUNK - co, length)
            data = self._read_at(foff + co, n)
            out += data
            if len(data) < n:
                break
            pos += n
            length -= n
        return bytes(out)
```

解密命令：

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -in core_memory.bin -out core_memory.txt
cat core_memory.txt
```

## 变体与关联

- EWF 压缩块（zlib/bzip2）、多段 E01/E02、EWF2 需要相应解压与段表；核心是“按 table 索引读取完整 chunk”。
- NTFS 删除恢复可换成 `$UsnJrnl`、`$LogFile`、卷影副本、回收站；数据库页覆盖时可从 WAL/日志/备份找副本。
- 加密容器可换成 VeraCrypt、age、GPG、7z；OpenSSL 格式可用 `Salted__` 头与 `-pbkdf2` 识别。
- 关联：部分磁盘镜像取证、NTFS 删除文件恢复、git 对象取证、OpenSSL 口令解密卡。

## 检测与防御

- 对关键数据做多副本/校验（git 对象、数据库 WAL、备份），避免单页覆盖导致不可恢复；磁盘镜像采集时保证完整写入与校验。
- 敏感记忆/密钥使用强 KDF 与足够口令熵；不要把硬件编号等公开信息直接作为口令组成部分。
- 取证时保留原始镜像与哈希链，记录 chunk 校验和；对不完整镜像使用只读解析器，避免二次破坏。
- 检测：异常大量 DNS/磁盘写入导致镜像截断、回收站中可疑副本、git 对象被删除但 pack 中仍有残留。
