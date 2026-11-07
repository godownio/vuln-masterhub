---
id: code-analysis-reverse-unpacking-pyinstaller-appended-zip-footer-dropper
title: PyInstaller 加载器：EXE 尾部追加 ZIP + 16 字节 footer（ZIP 大小/magic），解压到临时目录并启动诱饵与木马
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: pyinstaller-appended-zip-footer-stub-dropper
aliases:
- PyInstaller 附加 ZIP
- appended ZIP dropper
- 16 字节 footer
- '0xDEADBEEFCAFEBABE'
- packer_temp 目录
- villa.exe 释放器
- 诱饵 PPTX 木马
tags:
- pyinstaller
- dropper
- unpacking
- appended-zip
- footer
- magic
- temp-directory
- decoy
- malware
- python
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V193
  verified_at: '2026-11-06T23:52:45+08:00'
  notes: 已对照原文与图01-07核对；footer/magic/zip_size、packer_temp_*、BGL.exe与pptx一致；反编译行zip_start_pos用按位或，卡片已注明与常规布局差异并以PK/大小交叉验证；未运行样本。
---

## 一句话结论

用 PyInstaller 打包的恶意 EXE 可以在 PE 文件末尾再追加一个 ZIP，并在最后 16 字节写入“8 字节 ZIP 大小 + 8 字节 magic `0xDEADBEEFCAFEBABE`”的 footer；入口 `stub.py` 读取 footer、定位 ZIP、解压到 `%TEMP%\packer_temp_<pid>_<uuid>`，然后逐个 `os.startfile` 启动正常诱饵（如 PPTX）和恶意 EXE。分析时按 footer 的 magic/大小或 `PK\x03\x04` 即可把追加载荷完整取出。

## 原理

- **PyInstaller 外壳与额外 ZIP 是两层**：PyInstaller 自身会把 Python 解释器、PYZ、CArchive 打包进 EXE，入口脚本（本例 `stub.py`）由 PyInstaller 引导执行；攻击者又在整个 EXE 的末尾追加了一个独立的 ZIP，用来存放诱饵文档和恶意程序。PE 加载器会忽略 PE 映像之后的数据，所以追加 ZIP 不影响 EXE 正常运行。
- **16 字节 footer 定位 ZIP**：`stub.py` 用 `struct.calcsize('QQ')` 得到 16，`f.seek(-16, os.SEEK_END)` 读最后 16 字节，`struct.unpack('QQ')` 得到 `zip_size` 与 `magic_number`。原文样本的 footer 为 `D6 EE 99 00 00 00 00 00 | BE BA FE CA EF BE AD DE`，即 `zip_size=0x99EED6`、`magic=0xDEADBEEFCAFEBABE`（十进制 `16045690984503098046`）；脚本校验 magic 不匹配就退出，避免误把普通 PyInstaller 文件当载荷。
- **定位 ZIP 起点**：按 ZIP 布局，追加区起点应为 `file_size - 16 - zip_size`。原文反编译出的脚本写作 `zip_start_pos = (os.path.getsize(exe_path) or footer_size) | zip_size`，该表达式与常规布局不一致（可能是反编译失真或样本自定义偏移算法）；实际分析应以 footer 的 `zip_size`、文件末尾数据与 `PK\x03\x04` 签名交叉验证，不能盲信该行。
- **解压与启动**：脚本创建 `packer_temp_{os.getpid()}_{uuid.uuid4().hex}` 目录，把 ZIP 内所有成员解压进去；解压前用 `os.path.abspath` + `startswith` 做 Zip Slip 检查（拒绝跳出临时目录的成员名）。随后遍历目录，对每个文件调用 `os.startfile(full_path)`，于是诱饵 PPTX 被打开、恶意 `BGL.exe` 同时在后台运行。
- **为什么有效**：用户看到的是正常 PPTX，注意力被吸引；恶意 EXE 已在同一批 `startfile` 中启动。PyInstaller 的 Python 运行时让脚本逻辑难以静态看清，额外 ZIP 又使载荷不在 PE 节表中，常规 PE 解析/杀软静态扫描容易漏掉尾部数据。
- **样本实例**：`villa.exe` 18,031,013 字节，PyInstaller 2.1+/Python 3.11；appended ZIP 内含 `卡尔别墅.pptx`（正常文件，9.68MB）和 `BGL.exe`（131KB，UPX 壳），ZIP 成员时间分别为 2025-11-08。

## 触发条件

- 样本为 PyInstaller 打包的 Windows EXE，且文件尾部追加了 ZIP 与 16 字节 footer；footer 的 magic 为 `0xDEADBEEFCAFEBABE`（或变体自定义 magic）。
- 运行环境有 Python 运行时（PyInstaller 自带）；`%TEMP%` 可写；`os.startfile` 可用。
- 用户执行该 EXE；系统未拦截向 `%TEMP%` 写入/从临时目录启动可执行文件。
- 分析侧需要 PyInstaller 解包工具（pyinstxtractor-ng）与 Python 3.11 反编译器（pylingual；uncompyle6 不支持 3.11）。

## 利用步骤

1. 识别 PyInstaller：在样本中搜索 `PyInstaller`、`PYZ-00.pyz`、`MEIPASS` 等字符串；用 `pyinstxtractor-ng` 解出 CArchive/PYZ，定位入口 `stub.py` 的 pyc。
2. 反编译入口：Python 3.11 产物用 `pylingual` 转成 py；重点看 `struct.unpack('QQ', footer)`、magic 比较、`zipfile`、`os.startfile`。
3. 解析 footer：读取文件最后 16 字节，按小端 `QQ` 取 `zip_size` 与 `magic`；校验 magic `0xDEADBEEFCAFEBABE`。
4. 定位并提取追加 ZIP：优先按 `file_size - 16 - zip_size` 计算起点，检查是否为 `PK\x03\x04`；若不符，用 `binwalk`/`grep -abo $'PK\x03\x04'` 在文件尾部搜索 ZIP 中央目录/本地头，或按 `zip_size` 从尾部反推。
5. 解压 ZIP 并列出成员：正常诱饵文档与恶意 EXE（本例 `卡尔别墅.pptx`、`BGL.exe`），计算哈希、检查 PE/UPX/签名。
6. 复现/模拟：在隔离环境写一个只做“读 footer → 解压到临时目录 → 启动”的最小 stub（见 PoC），用于验证检测规则；不要运行原样本。
7. 继续分析子样本：BGL.exe 的 UPX 脱壳、shellcode 解密、C2 配置与后续阶段见关联卡片。

## PoC

解析 footer 并提取追加 ZIP（只读分析，未执行样本）：

```python
import io, struct, zipfile

data = open('villa.exe', 'rb').read()
zip_size, magic = struct.unpack('<QQ', data[-16:])
assert magic == 0xDEADBEEFCAFEBABE, hex(magic)
start = len(data) - 16 - zip_size
assert data[start:start+4] == b'PK\x03\x04', data[start:start+8].hex()
z = zipfile.ZipFile(io.BytesIO(data[start:start+zip_size]))
print(z.namelist())
z.extractall('villa_appended_zip')
```

最小加载器骨架（防御测试用，按原文逻辑整理；注意原文反编译表达式与常规布局的差异）：

```python
import io, os, struct, sys, uuid, zipfile

exe = sys.executable
with open(exe, 'rb') as f:
    f.seek(-16, os.SEEK_END)
    zip_size, magic = struct.unpack('QQ', f.read(16))
    if magic != 16045690984503098046:
        sys.exit()
    zip_start = os.path.getsize(exe) - 16 - zip_size
    f.seek(zip_start)
    blob = f.read(zip_size)

temp_dir = os.path.join(os.environ['TEMP'],
                        f'packer_temp_{os.getpid()}_{uuid.uuid4().hex}')
os.makedirs(temp_dir, exist_ok=True)
zipfile.ZipFile(io.BytesIO(blob)).extractall(temp_dir)
for name in os.listdir(temp_dir):
    os.startfile(os.path.join(temp_dir, name))
```

## 变体与关联

- 变体：footer 可用不同 magic（本例 `0xDEADBEEFCAFEBABE`）、不同字段顺序或长度；也可把 ZIP 换成 CAB/7z/自定义加密块，或把 ZIP 追加到 PNG/文档尾部。
- 变体：不打开诱饵，只解压并运行恶意 EXE；或先做反沙箱/延迟再 `startfile`。
- 变体：ZIP 成员名使用中文/正常文档名，诱饵与恶意文件同时启动，降低用户中断概率。
- 关联：[[code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract]]（PyInstaller CArchive/PYZ 解包）、[[code-analysis-reverse-unpacking-pyinstaller-repack-spec-carchive-toc]]（PyInstaller 重打包）、[[defense-forensics-pyinstaller-dropbox-dead-drop-dwservice]]（PyInstaller 双载荷与诱饵）、[[code-analysis-reverse-windows-valleyrat-staged-shellcode-codemark-reflective-pe]]（本例后续 ValleyRAT 链）。
- 边界：样本不是 PyInstaller、footer/magic 被改、追加数据被加密/压缩、临时目录不可写或被 EDR 阻止、`os.startfile` 被策略禁用时，这条链不成立。

## 检测与防御

- **静态检测**：扫描 PE 文件 overlay/尾部数据；YARA 规则匹配文件末尾 16 字节的 `magic`、尾部 `PK\x03\x04`、`packer_temp_` 字符串、`PyInstaller` + 追加 ZIP 组合；`binwalk`/`pefile` 检查 PE 节表之外的数据。
- **动态检测**：监控 `%TEMP%\packer_temp_*` 目录创建、ZIP 解压、同一进程短时间内 `ShellExecute/os.startfile` 打开文档并启动 EXE；关注 PyInstaller EXE 的子进程为 `%TEMP%` 下的未签名程序。
- **防御**：应用白名单/WDAC 限制未签名 PyInstaller EXE 与临时目录可执行文件；对下载的 EXE 做 MOTW/ATTACH 标记；禁用或限制 `os.startfile` 类行为；邮件/网关联动拦截带异常 overlay 的 PE。
- **响应**：提取追加 ZIP、隔离诱饵与恶意子样本、计算哈希并与情报比对；清理 `%TEMP%` 残留目录；按子样本（如 BGL.exe）继续做内存/网络排查。
