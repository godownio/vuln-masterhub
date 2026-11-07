---
id: ctf-pwn-awd-batch-scan-concurrent-exp-runner
title: AWD 批量利用编排：目标扫描 + 并发加载 exp.py + 结果收集
type: scenario
domain: ctf
path: ctf/pwn
technique: awd-batch-exploit-orchestration
tags:
- ctf
- awd
- pwn
- automation
- threading
- scanning
- exploit-runner
- python
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V91
  verified_at: '2026-11-05T19:54:33+08:00'
  notes: 已对照原文附录脚本核对：scan.txt 三种格式、ThreadPoolExecutor(100)/0.5s 探测与 banner 关键词、alive_targets.txt；exp_runner 用 spec_from_file_location 唯一模块名、临时替换 pwn.process→pwn.remote、inspect.signature 三种 exp 签名、recvrepeat(0.5) 兜底、close；scan_and_attack 20 线程+Lock 写 success.txt；snake_login 缓冲 socket 登录/口令泄露/命令执行。属 AWD 批量编排工具卡，未执行。原文无组件版本区间，未设 affected_versions；frontmatter无sources/source_url。
url: /docs/ctf/pwn/ctf-pwn-awd-batch-scan-concurrent-exp-runner/
draft: false
kb_aliases:
- AWD 批量打靶
- 批量 exp 框架
- 并发打靶
- scan_and_attack
- exp_runner
- pwn.process 重定向
---

## 一句话结论

AWD 场景可以把“目标扫描、并发调度、exp 复用、结果收集”拆成独立模块：扫描器解析 CIDR/IP 段/host:port 并用线程池探测存活，执行器为每个目标动态加载同一份 `exp.py`，把 `pwn.process` 临时重定向到 `pwn.remote(host, port)`，并发调用 `exp()` 并把成功输出写入结果文件。

## 原理

- **目标解析**：`scan.txt` 支持三种行格式：CIDR（`10.0.0.0/24`）、IP 范围（`10.0.0.1-10.0.0.9` 或 `10.0.0.1-9`）、`host:port`；解析后去重，统一成 `(host, port)`。
- **存活探测**：`ThreadPoolExecutor(max_workers=100)` 并发 `socket.create_connection`（超时 0.5s），读取 banner；命中业务关键词（如 `welcome to the game`、`2.login admin`）或端口可连即视为存活，结果写入 `alive_targets.txt`。
- **exp 复用**：同一份 `exp.py` 原本用 `pwn.process('./pwn')` 本地调试；执行器用 `importlib.util.spec_from_file_location` 为每个目标加载一个唯一模块名，临时把 `pwn.process` 替换成 `pwn.remote(host, port)` 的包装器，执行完恢复原函数，避免修改 exp 源码。
- **兼容多种 exp 签名**：通过 `inspect.signature` 判断 `exp(host, port)`、`exp((host, port))` 还是 `exp()`；若 exp 返回 `None`，则从模块的 `io` 读取剩余输出（`recvrepeat(0.5)`），最后关闭连接。
- **并发与结果收集**：`scan_and_attack.py` 用 20 个线程对存活目标并发调用 `run_exp`，用 `threading.Lock` 保护 `success.txt` 的追加写入；每个目标独立加载模块，避免全局状态串扰。
- **业务专用交互层**：`snake_login.py` 封装带缓冲的 socket（`recv_until`/`recv_some`/`send_line`），实现“选择 admin → 登录 → 泄露口令 → 执行命令”，把协议细节与调度框架解耦。

## 触发条件

- AWD/CTF 场景有多个同构目标，端口与 banner 已知或可探测；
- 已有可本地复现的 `exp.py`，且核心交互能封装成函数；
- 允许并发连接，目标未做连接频率限制（或控制在合理并发内）；
- 需要快速覆盖大量靶机并收集成功标志（如 flag 回显）。

## 利用步骤

1. 把目标写入 `scan.txt`（CIDR、IP 段或 host:port），确认端口与 banner 关键词。
2. 运行扫描器：多线程连接、读取 banner、保存 `alive_targets.txt`。
3. 把 exp 的核心逻辑封装成 `exp()`；保留 `io` 为模块级变量，便于执行器读取输出。
4. 执行器为每个目标动态加载 `exp.py`，临时替换 `pwn.process` 为 `pwn.remote`，调用 `exp()`。
5. 主调度器读取存活列表，用线程池并发执行；成功输出加锁写入 `success.txt`。
6. 对失败目标记录异常，调整超时/并发/协议处理；对成功目标保留输出用于提交或复核。

## PoC

核心执行器骨架（按原文框架简化）：

```python
import importlib.util, inspect, threading, uuid
from pathlib import Path
import pwn

EXP_FILE = Path("exp.py")
LOCK = threading.Lock()

def load_exp(host, port):
    name = f"_awd_exp_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(name, EXP_FILE)
    mod = importlib.util.module_from_spec(spec)
    original = pwn.process
    def fake_process(*args, **kwargs):
        return pwn.remote(host, port, *args[1:], **kwargs)
    pwn.process = fake_process
    try:
        spec.loader.exec_module(mod)
    finally:
        pwn.process = original
    if hasattr(mod, "it"):
        mod.it = lambda: mod.io.recvrepeat(0.5)
    return mod

def run_exp(host, port):
    mod = load_exp(host, port)
    try:
        params = list(inspect.signature(mod.exp).parameters.values())
        n = len([p for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)])
        if n >= 2:   return mod.exp(host, port)
        if n == 1:   return mod.exp((host, port))
        return mod.exp()
    finally:
        if hasattr(mod, "io"):
            try: mod.io.close()
            except Exception: pass
```

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def attack(host, port):
    try:
        out = run_exp(host, port)
        with LOCK:
            open("success.txt", "a", encoding="utf-8").write(f"[{host}:{port}] {out}\n")
        return True, host, port
    except Exception as e:
        return False, host, port

with ThreadPoolExecutor(max_workers=20) as pool:
    jobs = [pool.submit(attack, h, p) for h, p in alive_targets]
    for job in as_completed(jobs):
        print(job.result())
```

扫描器要点：`ipaddress.ip_network` 展开 CIDR、`ipaddress.ip_address` 展开 IP 段、`socket.create_connection` + `recv` 匹配 banner；结果写入 `alive_targets.txt`。

## 变体与关联

- 变体：用 `asyncio`/`aiohttp` 替代线程池提高并发；用进程池隔离每个 exp，避免 pwn 全局上下文/信号处理串扰。
- 变体：执行器可支持多份 exp、按目标指纹选择不同 exp；结果可写入 CSV/数据库并自动提交 flag。
- 变体：扫描器可加入指纹识别（banner、HTTP 头、端口组合），减少无效 exp 尝试。
- 关联：AWD 二进制补丁、exp 本地调试、目标指纹识别。
- 边界：并发过高可能触发目标限流/封禁；AWD 中需遵守比赛规则与授权范围。

## 检测与防御

- 防守方检测：短时间内大量来源 IP 对同一端口建立连接、banner 探测失败率异常、同一 payload 在多目标重复出现；可部署连接频率限制、蜜罐与异常连接告警。
- 防守方加固：及时打补丁、限制错误回显、增加随机化/ASLR、监控批量 exp 的典型交互序列。
- 比赛合规：仅在授权靶场/比赛环境使用，控制并发并遵守赛事规则。
