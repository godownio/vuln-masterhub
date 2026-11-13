---
id: tools-burp-mitmdump-addon-launcher-breakpoint-debug
title: mitmdump addon 断点调试：用 Python 启动器内嵌调用 mitmdump([...]) 启动，-s 脚本即可在 IDE 下断点
type: scenario
domain: tools
path: tools/burp
technique: mitmdump-addon-inprocess-launcher-breakpoint-debug
aliases:
- mitmdump 断点调试
- mitmproxy addon debug
- mitmdump 启动器脚本
- mitmdump -s 脚本调试
- mitmproxy tools main mitmdump
tags:
- mitmproxy
- mitmdump
- addon
- debug
- breakpoint
- python
- proxy
- burp
- encryption
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V618
  verified_at: '2026-11-12T21:04:02+08:00'
  notes: 已对照原文 content.md 与全部 21 张图核对：Debug 段启动器代码 from mitmproxy.tools.main import mitmdump + sys.path.append(os.path.dirname(os.path.abspath(__file__))) + mitmdump(['-s','enc.py','-p',str(9091)]) 与下游 ['-s','dec.py','-p',str(7071),'--mode','upstream:http://127.0.0.1:8080'] 均与原文逐字一致；图 20/21 为 PyCharm Debugger 在 enc.py/dec.py request 钩子命中断点，Frames 显示 request→invoke_addon→trigger_event 调用栈，证明卡片的'同进程加载 addon 使断点生效'结论成立。dedup 20 候选全 new，dup-scan 无 pair；worker 跳过的上下游双代理链场景已核对由既有 verified 卡 tools-burp-mitmproxy-dual-chain-aes-cbc-yakit-hotload-phone-bruteforce 与 tools-burp-encrypted-api-proxy-decrypt-resign 完整覆盖（四钩子/--mode upstream/重签防重放），跳过合理。未验证点：未在本机安装 mitmproxy 复现断点。
---

## 一句话结论

直接用 `mitmdump -s enc.py` 从命令行启动时，addon 脚本运行在另一个解释器进程里，IDE 调试器附着的进程不是它，断点不会命中；改为写一个 Python 启动器，先 `sys.path.append` 脚本目录，再在当前进程内调用 `mitmproxy.tools.main.mitmdump([...])`，addon 的 `request`/`response` 钩子就会加载进调试器所在进程，可以在 `enc.py`/`dec.py` 里正常下断点单步调试。

## 原理

- `mitmdump` 命令行本身只是 `mitmproxy.tools.main` 的入口封装：解析参数后由 `ScriptLoader` 在进程内 exec 加载 `-s` 指定的 addon 脚本，再启动代理事件循环。
- 从终端敲 `mitmdump` 时，操作系统创建的是一个新的 Python 解释器进程；IDE 的调试器只 attach 到自己启动的那个进程，所以即使 `-s` 指向当前打开的项目文件，断点也落不到运行中的 mitmdump 进程里。
- 在启动器脚本中直接 `from mitmproxy.tools.main import mitmdump` 并调用 `mitmdump([...])`，等于把 CLI 的解析与代理启动逻辑放在当前解释器进程内执行；addon 脚本随后被同一进程加载，IDE 断点自然生效。
- `sys.path.append(os.path.dirname(os.path.abspath(__file__)))` 把启动器所在目录加入模块搜索路径，保证 `-s enc.py` 的相对路径和 addon 内部的 `import` 都能解析。
- 上游、下游两个代理各写一个启动器即可分别调试；启动器里的参数列表与命令行完全等价（`-p`、`-s`、`--mode upstream:...`、`--ssl-insecure`）。

## 触发条件

- 正在开发或排查 mitmproxy/mitmdump addon（`request`/`response` 钩子里做解密、加密、签名重算等），需要单步调试而不是只靠 `ctx.log.info` 打日志。
- 使用 PyCharm、VS Code（debugpy）等能调试“自己启动的 Python 进程”的 IDE。
- addon 脚本与启动器在同一目录，或显式把脚本目录加入 `sys.path`。
- 环境已安装 mitmproxy 对应版本，端口、上游代理与 CA 证书配置就绪。

## 利用步骤

1. 正常编写 addon 脚本（如 `enc.py`、`dec.py`）：定义处理类（`request`/`response` 方法）并保留 `addons = [Mimit(),]`。
2. 在同目录创建上游启动器 `run_enc.py`：`from mitmproxy.tools.main import mitmdump`，追加脚本目录到 `sys.path`，再调用 `mitmdump(['-s', 'enc.py', '-p', '9091', '--ssl-insecure'])`。
3. 下游启动器同理，参数换成 `['-s', 'dec.py', '-p', '7071', '--mode', 'upstream:http://127.0.0.1:8080']`。
4. 在 addon 的 `request`/`response` 函数内下断点，用 IDE 的 Debug 模式运行启动器；触发一次代理流量，断点命中后可看到调用栈从 mitmproxy 的事件分发进入 addon 方法（`trigger_event`/`ScriptLoader` 帧）。
5. 调试完成后，恢复用 `mitmdump -p ... -s ...` 命令行方式跑批量或长期运行，避免调试器暂停阻塞流量处理。

## PoC

上游 addon 调试启动器：

```python
import sys
import os
from mitmproxy.tools.main import mitmdump

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
print(os.path.dirname(os.path.abspath(__file__)))

mitmdump(['-s', 'enc.py', '-p', str(9091)])
```

下游 addon 调试启动器（带上游代理模式）：

```python
import sys
import os
from mitmproxy.tools.main import mitmdump

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
print(os.path.dirname(os.path.abspath(__file__)))

mitmdump(['-s', 'dec.py', '-p', str(7071), '--mode', 'upstream:http://127.0.0.1:8080'])
```

说明：在 IDE 中以调试模式运行上述启动器（而非直接运行 `mitmdump` 命令），再在 `enc.py`/`dec.py` 的钩子函数内下断点；断点命中后即可单步查看 `flow` 对象、修改加解密逻辑。仅在自有测试环境使用。

## 变体与关联

- **完整代理链场景**：上游/下游两个 mitmdump 与 Burp 串联的加解密链路见 [[tools-burp-mitmproxy-dual-chain-aes-cbc-yakit-hotload-phone-bruteforce]]（四钩子 + `--mode upstream` + 白名单）与 [[tools-burp-encrypted-api-proxy-decrypt-resign]]（透明解密/重签与防重放字段重算）；本卡是开发这两类 addon 时的调试配套技巧。
- **变体**：只调一个代理时只写一个启动器；需要同时调上下游时两个启动器分别在 IDE 的不同运行配置中启动，参数中的 `--mode upstream:` 指向 Burp 或另一层代理。
- **边界**：启动器只解决“断点附错进程”的问题；证书错误、端口占用、上游代理不通属于运行配置问题，仍要按 `--ssl-insecure`、`--mode upstream:...` 与 CA 信任逐一排查。
- **替代**：不方便用调试器时，可在钩子里临时加 `ctx.log.info` 打印 `flow.request.url`、字段值与加解密中间结果，效果接近但无法单步。

## 检测与防御

- 本卡是开发/测试侧技巧，对目标服务端没有额外行为特征；断点暂停代理会阻塞流量，批量测试或长期挂代理时不要开启调试模式。
- 服务端视角与普通 mitmproxy 代理一致，防御仍依赖证书固定、双向认证与请求签名等既有手段，不因客户端调试方式改变。
- 仅限授权测试环境使用 `--ssl-insecure`（会跳过上游证书校验），不要在含敏感流量的生产网络中长期开启。
