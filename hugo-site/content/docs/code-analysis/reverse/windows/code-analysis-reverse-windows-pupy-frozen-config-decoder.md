---
id: code-analysis-reverse-windows-pupy-frozen-config-decoder
title: Pupy RAT frozen Python 载荷识别与配置解码：pupyrat-config-decoder（Python2 + pylzma/marshal）提取 C2/参数/证书
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: pupy-frozen-config-decoder
tags:
- malware-analysis
- reverse
- windows
- pupy
- rat
- config-extraction
- python2
- pylzma
- marshal
- frozen-python
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V280
  verified_at: '2026-11-08T02:06:29+08:00'
  notes: 已对照原文核对；img05/06 特征、img07/08 报错与修改、img09 解出 launcher_args/delays/证书均符；Pupy 3.x 版本表述原文未明确，属合理推断；未运行样本/解码器
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-pupy-frozen-config-decoder/
draft: false
kb_aliases:
- Pupy RAT 配置提取
- pupyrat-config-decoder
- pupy frozen 模块
- _memimporter
- pylzma marshal 配置
- Python2.7 marshal 解码
---

## 一句话结论

样本释放的 `file` 中出现 `pupy`、`_memimporter`、`frozen`、`pupy.error`、`revision`、`__main__` 等标记以及大量 `Py*` CPython API，可判定为 Pupy RAT 的 frozen Python 载荷；用 `pupyrat-config-decoder` 在 Python2.7 环境执行 `python2 main.py <file>`（不要用 `./main.py`），即可对配置数据做 `pylzma.decompress` + `marshal.loads` 并解出 `launcher_args`（C2 host/port、`-t ssl`）、`cid`、`delays`、`debug` 与证书。若第 28 行 `decompile(2.7, ...)` 报 `AssertionError: 2.7 does not smell like code`，把该行改为 `print(tmp)` 仍能拿到配置字典。

## 原理

- **Pupy 的 frozen Python 形态**：Pupy 是基于 Python 的远控/后渗透框架，载荷把 Python 模块冻结进可执行文件，运行时通过 `_memimporter` 和 `PyEval_EvalCode`/`PyRun_InteractiveLoop` 等 CPython API 加载执行。`file` 中同时出现 `pupy`、`pupy.error`、`frozen`、`revision`、`__main__` 以及 `PyString_FromStringAndSize`、`PyDict_New`、`PyModule_AddStringConstant`、`PyList_Append`、`PyEval_EvalCode`、`PyRun_InteractiveLoop` 等导入，是识别 Pupy 的关键特征。
- **配置的存储形式**：Pupy 把配置（C2、launcher 参数、延迟、调试开关、证书等）压缩后序列化。解码器定位到配置数据后执行 `pylzma.decompress(data[index:])` 得到 marshal 字节流，再 `marshal.loads(data)` 还原成 Python 对象，最后可交给 uncompyle6 反编译或直接打印。
- **为什么必须用 Python2.7**：`marshal` 的字节格式与 Python 主版本绑定，Pupy 3.x 的配置是 Python2.7 的 marshal 数据，解码器内部也按 `decompile(2.7, tmp, ...)` 处理。用默认 Python3 解释器（例如直接 `./main.py`）会走到 `assert iscode(co), "2.7 does not smell like code"`，表现为 `AssertionError: 2.7 does not smell like code`；改用 `python2 main.py <file>` 才能正确还原。
- **第 28 行兼容处理**：uncompyle6 对部分 marshal 对象仍会断言失败，此时把 `decompile(2.7, tmp, sys.stdout, showast=False)` 改成 `print(tmp)`，跳过反编译、直接打印 marshal 出来的字典，同样能得到配置。
- **为什么值得提取**：配置里的 `--host`/端口和 SSL 参数是 C2 IOC，`delays` 是心跳/重连策略，证书可用于进一步识别基础设施；整个过程静态完成，不需要运行样本或连接 C2。

## 触发条件

- 已取得疑似 Pupy 的样本文件（PE/ELF，或样本释放的 `file`），可做 strings/IDA 静态分析；样本可能带 UPX 壳或 VM 检测，但不影响对释放文件的静态配置提取。
- 具备 Python2.7 运行环境，安装 `pupyrat-config-decoder` 及其依赖（`pylzma`、`uncompyle6` 等）。
- 配置数据的压缩/序列化格式与解码器支持的 Pupy 版本一致（偏移或压缩方式随版本可能变化）。
- 仅在授权取证环境中分析；C2 地址只作 IOC，不应实际连接。

## 利用步骤

1. 对样本做基础静态分析（必要时先 UPX 脱壳），在 strings/IDA 中查找 `pupy`、`_memimporter`、`frozen`、`pupy.error`、`revision`、`__main__` 与 `PyEval_EvalCode`、`PyRun_InteractiveLoop` 等特征，确认 frozen Python/Pupy 载荷。
2. 取得样本释放的 `file`（或从释放目录/内存中提取），记录大小与哈希。
3. 准备 Python2.7 环境并安装解码器依赖。
4. 用 `python2 main.py <file>` 运行解码器，避免直接 `./main.py` 触发版本问题。
5. 若第 28 行 `decompile(2.7, tmp, sys.stdout, showast=False)` 报 `AssertionError: 2.7 does not smell like code`，改为 `print(tmp)` 后重跑。
6. 从输出字典读取 `launcher_args` 中的 `--host`/端口、`-t ssl`，以及 `cid`、`delays`、`debug`、`-----BEGIN CERTIFICATE-----` 证书等字段，整理为 IOC。
7. 若偏移不匹配，按 Pupy 版本调整解码器中定位配置的偏移；必要时先 `marshal.loads` 再手工遍历字典。

## PoC

```bash
# 错误方式（默认解释器/Python3 环境）：line 28 断言失败
# AssertionError: 2.7 does not smell like code
./main.py '/path/to/file'

# 正确方式：Python2.7 环境
python2 main.py '/path/to/file'
```

```python
# 解码器核心（原文第 26-28 行）
data = pylzma.decompress(data[index:])
tmp = marshal.loads(data)
print(tmp)   # 原文此处为 decompile(2.7, tmp, sys.stdout, showast=False)
```

```text
[{'launcher_args': ['--host', '<C2-IP>:<port>', '-t', 'ssl'],
  'cid': 11...,
  'delays': [(10, 5, 10), (50, 30, 50), (-1, 150, 300)],
  'debug': False,
  '-----BEGIN CERTIFICATE-----\n...'}]
```

> 说明：原文未给出样本哈希，配置中的地址仅作 IOC；未在本机运行样本或连接 C2。

## 变体与关联

- 同类配置提取：[[code-analysis-reverse-windows-remcos-settings-config-extraction]]、[[code-analysis-reverse-windows-njrat-vbnet-dnspy-install-c2-analysis]] 覆盖 Remcos/NjRAT 的配置与 C2 提取，本卡是 Pupy 的 frozen Python + pylzma/marshal 格式，工具链与偏移不同。
- Python marshal 样本：[[code-analysis-reverse-unpacking-python-nested-marshal-consts-chain]]、[[code-analysis-reverse-unpacking-pyinstaller-pyd-xor-marshal-code-object]] 处理其他打包/多层 marshal 的 Python 恶意样本；本卡侧重 Pupy 配置字典的直接还原。
- 同篇的 PNG LSB 下载信息提取见 [[ctf-forensics-png-lsb-zsteg-download-url-openpgp-payload]]（本卡只处理释放的 `file` 配置，不包含 PNG 分析）。
- 变体：uncompyle6 可用且版本匹配时直接反编译配置；不可用时 `print(tmp)` 打印字典。Pupy 版本变化会改变偏移/压缩格式，需要调整解码器。
- 边界：没有 Python2.7 环境、配置被二次加密、或解码器不支持该 Pupy 版本时，可能无法直接得到配置；此时可按 `pylzma`/`marshal` 手工处理。

## 检测与防御

- 检测：文件字符串/导入表中出现 `pupy`、`_memimporter`、`pupy.error`、`frozen` 与大量 `Py*` API；文件中存在 `pylzma`/`marshal` 特征；配置中出现 `--host`/`-t ssl`、异常 `delays` 与内嵌证书。
- 防御：EDR 拦截 frozen Python/Pupy 载荷与未签名 Python 运行时；限制 Python2.7 环境；对下载/邮件附件做多引擎扫描；封禁提取出的 C2 IP/端口与证书指纹。
- 响应：隔离主机并提取样本与释放文件；离线用解码器提取配置；封禁 C2；检查是否存在 Pupy 的横向移动/凭证窃取模块。
- 该场景仅用于恶意样本分析与授权取证，不要运行样本或连接生产 C2。
