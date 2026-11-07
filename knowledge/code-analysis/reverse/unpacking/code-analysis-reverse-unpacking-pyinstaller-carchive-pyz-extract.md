---
id: code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract
title: PyInstaller EXE 识别与解包：CArchive/PYZ/pyc 提取还原源码
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: pyinstaller-unpack-extract
aliases:
- PyInstaller 解包
- pyinstxtractor 使用
- CArchive 提取
- PYZ.pyz 提取
- pyc 反编译
- PyInstaller EXE 结构
tags:
- reverse
- unpacking
- pyinstaller
- python
- pyc
- carchive
- pyz
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
  verified_at: '2026-11-05T19:55:38+08:00'
  notes: 已对照原文与5张图核对：PyInstaller bootloader/CArchive/overlay 结构、PYZ/pyc 关系、pyinstxtractor 输出（PyInstaller 2.1+、Python 3.13、CArchive 10 文件/PYZ 112 文件）、入口 pyc 与 PYZ.pyz_extracted 提取结果（图1/4）均与卡片一致；pyc 16 字节头与 marshal 兜底分析可行。未验证点：未本机运行 pyinstxtractor/反编译；frontmatter 无 sources/source_url。
---

## 一句话结论

PyInstaller 打包的 Windows EXE 把 Python 字节码放在 PE overlay 的 CArchive 中（含 PYZ、python DLL、pyd 与数据文件，尾部为 TOC 和 Cookie）；用 pyinstxtractor 或手工解析 Cookie/TOC 即可提取 pyc 与 PYZ 内容，再反编译 pyc 还原业务逻辑。

## 原理

- PyInstaller 生成的 EXE 仍是标准 PE：`.text` 段是 PyInstaller 自带的 C 语言 bootloader，负责定位自身资源、解包 CArchive、加载 Python DLL、执行入口 pyc；随后是常规的 `.rdata`、`.rsrc`、`.reloc` 等段。
- PE 最后一个节区之后是 overlay 区域，即 CArchive。它依次存放 PYZ.pyz（多个 pyc 的压缩归档）、python DLL、pyd、依赖 DLL、数据文件，末尾是 TOC（目录表）和 Cookie。
- Cookie 记录 magic、归档总长、TOC 偏移、TOC 长度、Python 版本、python lib 路径等信息；bootloader 依靠 Cookie 找到 TOC，再按 TOC 中每个条目的偏移/压缩长度/原始长度/压缩标志/类型码（如 PYSOURCE、PYMODULE、BINARY、DATA）定位和解压数据。直接改 overlay 内容而不修 TOC 会让 bootloader 读到错误偏移。
- pyc 文件由 16 字节头部（magic、flags、时间戳/哈希、源码大小等）加 marshal 序列化的代码对象组成；PYZ 归档内通常只存剥离头部的纯 marshal 数据，所以提取后需要还原或直接按 marshal 读取。
- 运行时用户字符串不在 `.text` 或 `.rdata` 的明文里，而在 PYZ 内的 pyc 字节码中，因此 IDA 直接搜字符串通常搜不到；动态调试能在 Python 加载后看到字符串，但 x64dbg 无法直接 patch 字节码逻辑，需要先解包。
- pyinstxtractor 读取 Cookie 与 TOC，解出 CArchive 各条目，并展开 PYZ.pyz 到 `PYZ.pyz_extracted`；入口脚本（如 `simple.pyc`）与 `pyiboot01_bootstrap.pyc`、`pyi_rth_*.pyc`、`pyimod*.pyc` 等会一起出现。

## 触发条件

- 目标 EXE 由 PyInstaller 打包（onefile 或 onedir 均可），可用 DIE/strings/PE overlay 特征识别。
- 目标未使用 PYZ 加密，或已知加密密钥。
- 允许在本地运行提取工具；反编译 Python 版本有对应的反编译器或可改用 marshal/dis 分析。

## 利用步骤

1. 用 DIE（Detect It Easy）查看编译器/打包器信息；PyInstaller 样本常显示 PyInstaller/Python 相关标记。也可用 `strings` 搜 `pyiboot`、`pyi_rth`、`PYZ` 等特征，并观察 PE overlay 是否异常大。
2. 用 StudyPE/PEView 等查看节表，确认最后一个节区结束位置与 overlay 起点；overlay 即 CArchive 所在。
3. 运行 `python pyinstxtractor.py target.exe`，读取输出中的 PyInstaller 版本、Python 版本、CArchive 文件数、PYZ 文件数与入口点候选。
4. 在生成目录中定位入口 pyc（如 `simple.pyc`）与 `PYZ.pyz_extracted`；`pyc` 可交给 pycdc、uncompyle6、decompyle3 或支持对应 Python 版本的在线反编译服务。
5. Python 3.13 等较新版本的 pyc 可能不被老反编译器支持；可先用 `marshal.loads(pyc[16:])` 读取 code object，再用 `dis` 反汇编，或换用更新的 pycdc。
6. 阅读还原出的源码，定位校验逻辑、密钥/常量、网络接口与敏感数据；如需修改逻辑，进入二次打包流程（见关联卡）。

## PoC

```bash
# 1) 识别与解包
python pyinstxtractor.py simple.exe

# 典型输出：
# [+] Pyinstaller version: 2.1+
# [+] Python version: 3.13
# [+] Found 10 files in CArchive
# [+] Possible entry point: simple.pyc
# [+] Found 112 files in PYZ archive

# 2) 查看提取结果
ls simple.exe_extracted/
# simple.pyc  pyiboot01_bootstrap.pyc  pyi_rth_inspect.pyc  PYZ.pyz_extracted/ ...

# 3) 反编译入口 pyc（按 Python 版本选择工具）
pycdc simple.exe_extracted/simple.pyc
```

```python
# 反编译器不支持新版本时的兜底：直接读 marshal code object
import marshal, dis
with open("simple.pyc", "rb") as f:
    header = f.read(16)
    code = marshal.loads(f.read())
dis.dis(code)
```

## 变体与关联

- 变体：onefile 与 onedir 的产物布局不同；onefile 的依赖也在 CArchive 中，onedir 可能把部分文件放在目录里。
- 变体：PYZ 加密（`--key`）时，提取出的 pyc 需要先用密钥解密；密钥可能硬编码在 bootloader/脚本中，需进一步逆向。
- 变体：不同 PyInstaller 版本的 Cookie/TOC 结构有差异（2.1+ 与更新版本），手工解析应以目标版本 PyInstaller 源码中的 `CArchiveReader`/`CArchiveWriter` 常量为准。
- 关联：[[code-analysis-reverse-unpacking-upx-manual]]（另一种可执行文件壳的脱壳流程）、[[code-analysis-reverse-unpacking-pyinstaller-repack-spec-carchive-toc]]（提取后的 pyc 修改与二次打包）。
- 边界：解包只还原 Python 层代码；pyd/DLL 仍是原生二进制，业务逻辑若在 pyd 中需另做逆向。新版 Python 的字节码与反编译器兼容性是常见卡点。

## 检测与防御

- 检测：PE overlay 中存在 PYZ/CArchive 特征、`pyiboot`/`pyi_rth` 字符串、异常大的附加数据区；运行时加载 python DLL 并执行内存中的 marshal 代码。
- 修复/缓解：不要把授权判断、密钥或敏感算法只放在客户端 pyc 中；关键校验放服务端；对客户端完整性做签名校验。
- 加固：代码签名与哈希白名单、反调试/反篡改只能提高成本，不能作为安全边界；PyInstaller 打包本身不是保护措施。
