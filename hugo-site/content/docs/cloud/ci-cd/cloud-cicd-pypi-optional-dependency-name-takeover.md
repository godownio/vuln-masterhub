---
id: cloud-cicd-pypi-optional-dependency-name-takeover
title: python-json-logger 可选依赖名被弃用后遭抢注导致安装期代码执行（CVE-2025-27607）
type: scenario
domain: cloud
path: cloud/ci-cd
technique: pypi-dependency-name-takeover
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
tags:
- python
- pypi
- pip
- supply-chain
- dependency-confusion
- rce
- cve-2025-27607
cve:
- CVE-2025-27607
affected_versions: python-json-logger 3.2.0、3.2.1（3.3.0 修复）
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:24:38+08:00'
  notes: 已对照原文核对：CVE-2025-27607、3.2.0/3.2.1 受影响与 3.3.0 修复、optional-dependencies dev 声明 msgspec-python313-pre、包被删除后名称可抢注、commit 移除但未发版；原文无在野 PoC，卡内最小 PoC 为按原理构造（原文本机未执行）；affected_versions 已按原文设置。
url: /docs/cloud/ci-cd/cloud-cicd-pypi-optional-dependency-name-takeover/
draft: false
kb_aliases:
- CVE-2025-27607
- python-json-logger 供应链漏洞
- msgspec-python313-pre 抢注
- PyPI 依赖名劫持
- 弃用包名抢注
- 可选依赖投毒
---

## 一句话结论

python-json-logger 3.2.0/3.2.1 在 `pyproject.toml` 的可选依赖 `dev` 中声明了 `msgspec-python313-pre`；该包被原作者从 PyPI 删除后包名处于未占用状态，而仓库虽已移除依赖却未发布新版本，导致 `pip install python-json-logger[dev]` 会从 PyPI 拉取同名包。攻击者抢注该名称并植入 `setup.py`/`__init__.py` 恶意代码，即可在受害者安装或导入时执行任意代码。

## 原理

- PyPI 的包名是全局、先到先得的命名空间；一个包被删除后，其名称可以被任何人重新注册。依赖声明只记录包名与版本约束，不绑定发布者身份或内容哈希（除非显式使用哈希锁定）。
- python-json-logger 的 `[project.optional-dependencies]` 中声明 `dev = ["msgspec-python313-pre"]`。安装 `python-json-logger[dev]` 或需要 dev extra 时，pip 会解析并安装该依赖。
- 该依赖原本存在于 PyPI，随后被原作者删除；仓库中虽通过 commit 移除了这行声明，但 3.2.0/3.2.1 已经发布到 PyPI 的元数据不可变，仍指向该包名，且没有发布包含修复的新版本（3.3.0 才修复）。
- 攻击者注册同名包后，可以：
  - 在 `setup.py` 中放置安装期代码（pip 构建/安装 wheel 时执行）；
  - 在包 `__init__.py` 中放置导入期代码（业务 `import` 时执行）；
  - 通过 `entry_points`/console script 伪装成初始化命令，诱导执行。
- 由于包名与被删除的原包完全一致，受害者难以从名称识别异常；安装日志里也只是一个正常的依赖安装。
- 这是“废弃/未占用依赖名抢注”（dependency name takeover）的一种，与依赖混淆（dependency confusion）、typosquatting 同属供应链投毒，但利用的是**上游包删除后名称可被回收**这一特性。

## 触发条件

1. 受害者安装 python-json-logger 3.2.0/3.2.1 并启用 `dev` extra（`pip install python-json-logger[dev]`）。
2. 环境中 Python 版本满足该可选依赖的解析条件（原文提到 Python 3.13 环境下会自动安装；实际取决于包元数据与 pip 解析）。
3. 攻击者已在 PyPI 注册 `msgspec-python313-pre` 并发布恶意版本。
4. 安装环境可访问 PyPI（或使用会回源到公共 PyPI 的镜像/代理），且未启用哈希校验/私有源白名单。

## 利用步骤

1. 扫描热门包的依赖元数据，寻找已从 PyPI 删除但仍被引用的包名（404/未占用）。
2. 注册同名包，构造最小恶意发行版（`setup.py` + 包目录 + `__init__.py`）。
3. 在 `setup.py` 或 `__init__.py` 中放置载荷（反弹 Shell、窃取环境变量/CI Token、写后门等），并做静默异常处理避免影响安装。
4. 等待受害者执行 `pip install <package>[dev]` 或 CI 构建；pip 下载并执行恶意代码。
5. 载荷可进一步做环境判断（CI、Docker、生产标识）、延迟执行、持久化与外带。
6. 获取构建机/开发者主机权限、CI secrets、云凭据，继续横向。

## PoC

恶意包最小结构：

```text
msgspec-python313-pre/
├── setup.py
├── pyproject.toml
└── msgspec_python313_pre/
    └── __init__.py
```

`setup.py`：

```python
from setuptools import setup, find_packages
setup(
    name="msgspec-python313-pre",
    version="0.1.0",
    packages=find_packages(),
)
```

`msgspec_python313_pre/__init__.py`（导入期执行，最小验证）：

```python
import os
try:
    # 仅做无害标记，验证代码执行
    open(os.path.expanduser("~/.pwned_by_dep"), "w").write("ok")
except Exception:
    pass
```

受害者侧：

```bash
pip install 'python-json-logger[dev]==3.2.1'
# pip 解析 dev extra，下载并安装 msgspec-python313-pre
```

安装完成后检查 `~/.pwned_by_dep` 是否存在即可确认代码执行。原文未提供在野 PoC，上述为按文章原理构造的最小验证；反弹 Shell、数据外带、持久化等载荷属于通用后渗透实现，不是本漏洞特有。

## 变体与关联

- **依赖混淆**：私有包名在公共 PyPI 上被抢注，pip 优先拉取公共源的高版本。
- **Typosquatting**：注册与热门包相近的名称（拼写差异、连字符/下划线）。
- **废弃包接管**：上游删除包后名称可被回收，适用于任何仍引用该名称的历史版本。
- **可选依赖/extras 投毒**：只在安装 `[dev]`/`[test]` 时触发，生产环境可能不受影响，但 CI/开发机是高频目标。
- 与“恶意 PEP 517 构建后端在 pip 安装期执行代码”同属安装期供应链执行，只是入口从 build-backend 换成被抢注的依赖名。

## 检测与防御

- 锁定依赖并校验哈希：`pip freeze`/lockfile + `pip install --require-hashes -r requirements.txt`；避免无锁安装 extras。
- 使用私有 PyPI 镜像（devpi/Nexus/Artifactory）并配置上游白名单与包名审批，禁止直接回源公共 PyPI。
- 依赖审查：扫描 `pyproject.toml`/`setup.py` 中已弃用、404、未维护的包名；升级到修复版本（python-json-logger 3.3.0+）。
- 安装环境最小化：CI 构建容器禁网或仅允许白名单源；不在构建机长期保存云凭据/CI secrets；使用短期令牌。
- 监控安装期异常：`setup.py` 产生的网络连接、子进程、对 `~/.aws`、环境变量的批量读取；对新增 console_scripts 与包导入副作用做审计。
- 供应链层面启用包签名/来源证明（如 PyPI attestations）与 SBOM，定期比对依赖清单与实际安装内容。
