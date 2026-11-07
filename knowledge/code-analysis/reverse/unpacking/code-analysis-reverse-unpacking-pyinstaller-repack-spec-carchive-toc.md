---
id: code-analysis-reverse-unpacking-pyinstaller-repack-spec-carchive-toc
title: PyInstaller EXE 二次打包：spec TOC 注入与 CArchive 手工重写
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: pyinstaller-repack-carchive
aliases:
- PyInstaller 二次打包
- spec 文件替换 pyc
- a.pure TOC 注入
- CArchive TOC 重写
- pyc marshal 替换
- EXE 补丁重打包
tags:
- reverse
- repacking
- pyinstaller
- python
- pyc
- carchive
- toc
- pe
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V97
  verified_at: '2026-11-05T19:55:40+08:00'
  notes: 已对照原文与5张图核对：spec 路线（dumy.py、a.pure=TOC、PYMODULE 追加、a.scripts 强制 PYSOURCE、PYZ/EXE 重建）与原文完整 spec 一致；手工路线（CArchiveReader TOC 解析、pyc 前16字节截断、按 compress 标志 zlib 压缩、重算偏移/TOC/Cookie、bootloader+data+toc+cookie 拼接）与原文脚本一致；图5 验证输出 I am job!。未验证点：未本机复跑；卡内已注明 PyInstaller 内部常量跨版本需核对；frontmatter 无 sources/source_url。
---

## 一句话结论

修改 PyInstaller EXE 内的 pyc 后不能直接覆盖 overlay 字节，需要重打包：用 spec 文件清空 `Analysis` 的 `a.pure`/`a.scripts` 并注入自定义 pyc，或手工解析 CArchive TOC、替换目标条目的 marshal 数据并重算偏移/TOC/Cookie；两条路线都能生成可运行的修改版 EXE。

## 原理

- CArchive 的 TOC 为每个条目记录数据偏移、压缩长度、原始长度、压缩标志和类型码。直接替换 overlay 中的字节会改变后续条目的位置与长度，TOC 仍指向旧偏移，bootloader 会解压失败或执行错误数据；官方文档也明确提示直接修改 EXE 可能破坏 TOC。
- 入口脚本在 CArchive 中以 `PYSOURCE` 条目存在；普通模块在 `PYZ.pyz` 条目内。PYZ 内与 `PYSOURCE` 的数据通常是剥离了 16 字节 pyc 头部的纯 marshal 字节码，所以替换前要截断 pyc 头。
- 路线一（spec 重建）：PyInstaller 的 `Analysis` 要求一个 `.py` 入口文件，但没有源码时可以先放一个空 `dumy.py` 让 Analysis 通过；随后把 `a.pure` 置为空 TOC，再遍历工作目录把所有 `.pyc` 以 `PYMODULE` 类型追加进去；把 `a.scripts` 强制设为 `("simple", path/to/simple.pyc, "PYSOURCE")`，覆盖 dummy 入口。之后 `PYZ(a.pure, ...)` 和 `EXE(pyz, a.scripts, ...)` 会由 PyInstaller 重新生成正确的 PYZ、TOC 与 Cookie，无需手工算偏移。
- 路线二（手工重写）：读取原 EXE 尾部 Cookie 得到 TOC 偏移/长度与 Python 版本；按 `_TOC_ENTRY_FORMAT` 解析 TOC 条目；遍历数据区，命中目标条目时用新 marshal（若原条目 `compress` 为真则按 `_COMPRESSION_LEVEL` zlib 压缩）替换，其余条目原样拷贝；边拷贝边记录新偏移，生成新 TOC 条目列表；用 `_serialize_toc` 序列化新 TOC，重新计算归档总长与 TOC 偏移，pack 新 Cookie；最后按 `bootloader + 新数据区 + 新 TOC + 新 Cookie` 拼接写出。
- 两条路线都需要保持 Python 版本与目标一致：marshal 格式随 Python 版本变化，用不同版本 `compileall` 生成的 pyc 可能导致 bootloader 加载失败。手工路线还依赖 PyInstaller 内部常量/函数（`CArchiveReader`、`CArchiveWriter`），跨版本可能变化，应先确认目标 PyInstaller 版本。

## 触发条件

- 已完成 PyInstaller EXE 解包，拿到入口 pyc 或目标模块 pyc，并能修改/重新编译源码或直接编辑字节码。
- 目标未加密 PYZ，或已知 PYZ 密钥；否则需要先处理加密。
- spec 路线要求本机有与目标兼容的 PyInstaller 与 Python 环境；手工路线要求能导入目标版本的 PyInstaller 包以复用 TOC 常量与序列化函数。
- 修改后的 EXE 不要求通过原厂数字签名校验；若开启 Authenticode/完整性校验，需要额外处理签名。

## 利用步骤

1. 按解包流程拿到入口 pyc 与相关模块；修改源码后用 `python -m compileall simple.py` 生成新 pyc（或直接改字节码常量）。
2. 路线一（spec）：
   - 新建空 `dumy.py`，复制一份 `rebuild.spec`；
   - `pathex` 指向 pyc 所在目录；
   - `a.pure = TOC()`，遍历目录把每个 `.pyc` 以 `PYMODULE` 追加；
   - `a.scripts = TOC([("simple", os.path.join(work_dir, "simple.pyc"), "PYSOURCE")])` 强制真实入口；
   - 运行 `pyinstaller rebuild.spec`，检查 `dist/rebuild.exe` 是否按预期运行。
3. 路线二（手工）：
   - 截断 pyc 前 16 字节得到 marshal；
   - 用 `CArchiveReader(origin).toc` 确认目标条目存在，`reader._start_offset` 得到 bootloader 结束位置；
   - 解析 TOC，替换目标条目 blob 并重算偏移，序列化新 TOC 与新 Cookie；
   - 写出 `bootloader + data + toc + cookie`，运行验证。
4. 用字符串/行为对比验证修改生效（示例为把输出从 `I am bob!` 改为 `I am job!`）；若启动报错，优先检查 TOC 偏移/长度、压缩标志、marshal 版本与 Cookie 字段。
5. 若目标有签名校验，重打包后签名失效；需在授权环境内测试或处理签名/校验逻辑。

## PoC

```python
# 路线二核心：替换 CArchive 中目标 PYSOURCE 条目的 marshal 并重算 TOC/Cookie
import struct, zlib
from PyInstaller.archive.readers import CArchiveReader
from PyInstaller.archive.writers import CArchiveWriter

exe = open("simple.exe", "rb").read()
new_marshal = open("simple_marshal.bin", "rb").read()   # pyc[16:]
reader = CArchiveReader("simple.exe")
boot = reader._start_offset
cookie_len = CArchiveWriter._COOKIE_LENGTH
magic, _, toc_off, toc_len, py_ver, py_lib = struct.unpack(
    CArchiveWriter._COOKIE_FORMAT, exe[-cookie_len:])

toc_raw = exe[boot + toc_off: boot + toc_off + toc_len]
entries, ptr = [], 0
while ptr < len(toc_raw):
    hdr = struct.unpack(CArchiveWriter._TOC_ENTRY_FORMAT,
                        toc_raw[ptr:ptr + CArchiveWriter._TOC_ENTRY_LENGTH])
    elen, off, clen, ulen, comp, typecode = hdr
    name = toc_raw[ptr + CArchiveWriter._TOC_ENTRY_LENGTH: ptr + elen].rstrip(b"\x00").decode()
    entries.append((name, off, clen, ulen, comp, typecode.decode()))
    ptr += elen

data, new_toc = bytearray(), []
for name, off, clen, ulen, comp, tc in entries:
    if name == "simple":
        blob = zlib.compress(new_marshal, CArchiveWriter._COMPRESSION_LEVEL) if comp else new_marshal
        ulen = len(new_marshal)
    else:
        blob = exe[boot + off: boot + off + clen]
    new_toc.append((len(data), len(blob), ulen, comp, tc, name))
    data += blob

toc_bytes = CArchiveWriter._serialize_toc(new_toc)
new_toc_off = len(data)
new_total = new_toc_off + len(toc_bytes) + cookie_len
cookie = struct.pack(CArchiveWriter._COOKIE_FORMAT, magic, new_total,
                     new_toc_off, len(toc_bytes), py_ver, py_lib)
open("simple_patched.exe", "wb").write(exe[:boot] + bytes(data) + toc_bytes + cookie)
```

```python
# 路线一：spec 中注入 pyc（节选）
from PyInstaller.building.datastruct import TOC
import os
work_dir = os.path.abspath(".")
a = Analysis(['dumy.py'], pathex=[work_dir], ...)
a.pure = TOC()
for fname in os.listdir(work_dir):
    if fname.endswith(".pyc"):
        a.pure.append((fname[:-4], os.path.join(work_dir, fname), "PYMODULE"))
a.scripts = TOC([("simple", os.path.join(work_dir, "simple.pyc"), "PYSOURCE")])
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(pyz, a.scripts, a.binaries, a.zipfiles, a.datas, [], name='rebuild', console=True)
```

## 变体与关联

- 变体：只改常量/字符串时可改 pyc 的 marshal 常量池，避免重新编译整个模块；但需保证 code object 结构与 Python 版本一致。
- 变体：目标使用 PYZ 加密时，先用 `--key` 解密或从样本中提取密钥，再按同样流程替换；加密层会改变 blob 的处理方式。
- 变体：onedir 模式可直接替换 `dist/app/` 下的 pyc 或 PYZ 文件，不必重写整个 EXE，但需确认 bootloader 的校验与加载路径。
- 关联：[[code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract]]（前置的解包与 pyc 提取）、[[code-analysis-reverse-unpacking-upx-manual]]（另一类可执行文件壳的重建思路）。
- 边界：PyInstaller 内部 API 跨版本变动（Cookie/TOC 格式、`_serialize_toc` 签名），脚本需按目标版本调整；PE 校验和与数字签名在重打包后失效，可能被目标环境拒绝。

## 检测与防御

- 检测：对比 EXE 的 Authenticode 签名/哈希与发布版本；监控 PYZ/CArchive 结构异常（TOC 指向越界、条目压缩长度与原始长度不一致）；运行时检查 Python 字节码与官方构建的差异。
- 修复/缓解：客户端授权判断必须由服务端复核；不要依赖客户端 `if` 判断作为唯一授权边界；对关键配置和密钥使用服务端下发或硬件绑定。
- 加固：代码签名 + 完整性校验 + 反篡改检测提高修改成本；PyInstaller 的 CArchive 不是加密或签名机制，Cookie 只用于定位归档，不能防篡改。
