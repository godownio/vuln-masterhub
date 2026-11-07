---
id: defense-forensics-java-rat-encrypted-config-h2-db
title: Java 远控配置解密：AES-ECB version.txt + SHA1 派生 key 与 H2 agent.mv.db 历史配置
type: scenario
domain: defense
path: defense/forensics
technique: java-rat-encrypted-config-h2-db
tags:
- forensics
- java
- malware
- rat
- aes-ecb
- h2
- config-extraction
- c2
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:11:59+08:00'
  notes: 已对照原文与截图核对：YamlEncryptor 硬编码 seed=SHA1[:16] 作 AES-128 key、AES/ECB/PKCS5Padding+Base64、version.txt JSON 字段、agent.mv.db 的 LAUNCHER 用户与历史配置行均一致；已将原文/草稿误写的 config 表名按截图修正为 setting（x_key/x_value 键值行）。未验证点：H2 口令在截图中未直接可见（SQLiteHelper 截图展示的是 sqlite chacha20 key），未实际连接数据库。
url: /docs/defense/forensics/defense-forensics-java-rat-encrypted-config-h2-db/
draft: false
kb_aliases:
- MSRSCI 配置解密
- version.txt 解密
- YamlEncryptor
- agent.mv.db
- H2 数据库取证
- LAUNCHER 用户
- licenseKey
- jarLibs
---

## 一句话结论

MSRSCI.jar 这类 Java 远控把 C2/升级地址、licenseKey、插件列表等配置分别存在 `plugins/version.txt`（AES-ECB + Base64，key 由硬编码字符串 SHA1 前 16 字节派生）和 `plugins/data/agent.mv.db`（H2 数据库，LAUNCHER 用户密码在 `SQLiteHelper` 中硬编码）；解密/打开这两处即可还原当前与历史 C2、升级 URL、插件 JAR 列表和授权信息。

## 原理

- **version.txt**：`YamlEncryptor` 使用硬编码的 32 位 hex 字符串作为种子，`SHA1(seed)` 取前 16 字节作为 AES-128 key；`AES/ECB/PKCS5Padding` 加密后 Base64 编码写入 `version.txt`。解密后是 JSON，字段包括 `serverPath`、`licenseKey`、`servers`、`upgradeUrl`、`overTime`、`jarLibs`、`version`。
- 示例解密结果（IP 已脱敏）：
  ```json
  {
    "serverPath": "C:\\ClientManager_PSC",
    "licenseKey": "<32位hex>",
    "servers": "[{\"serverIp\":\"<C2 IP>\",\"enable\":true}]",
    "upgradeUrl": "http://<C2 IP>:9010/version/update",
    "overTime": "2025-11-02 13:00:00",
    "jarLibs": "[\"proxy-agent.jar\",\"lib-agent.jar\",\"xjar-pscp.exe\"]",
    "version": "2.1.0"
  }
  ```
- **agent.mv.db**：H2 数据库，用户 `LAUNCHER` 需要密码；密码相关代码在 `org/dromara/agent/util/SQLiteHelper` 中硬编码。用 H2 工具/驱动连接后，可读取 `setting` 表（`x_key`/`x_value` 键值行）：`serverIp`、`licenseKey`、`jarLibs`、`upgradeUrl`、`overTime`、`version`、`serverPath`、`isNewVersion`。
- 数据库中可能保留历史配置行（旧 C2 IP、旧 licenseKey、旧时间），与当前 version.txt 不一致；这些历史行是 C2 迁移/版本升级的证据，也是 IOC 来源。样本还可能删除 `xx_001`、`xx_002`、`process_log` 等表的数据以清理痕迹。
- **为什么能解密**：密钥/口令硬编码在客户端（`YamlEncryptor`、`SQLiteHelper`），分析者只要拿到 JAR/配置/DB 就能复现；即使 version.txt 被加密，key 派生逻辑也在同一 JAR 中。
- 这些配置直接暴露远控基础设施：C2/升级服务器、插件下载列表（`proxy-agent.jar`、`lib-agent.jar`、`xjar-pscp.exe`）、授权 key、安装路径；对溯源与阻断价值很高。

## 触发条件

- 拿到 Java 远控样本目录（含 `plugins/version.txt`、`plugins/data/agent.mv.db`、`MSRSCI.jar` 等）。
- 能读取 `YamlEncryptor`/`SQLiteHelper` 的硬编码 key/口令，或已从 JAR 中提取。
- 有 AES/Base64 与 H2 数据库工具（Python pycryptodome、H2 jar/驱动）。
- 授权 malware 分析/取证环境。

## 利用步骤

1. 定位 `plugins/version.txt` 与 `plugins/data/agent.mv.db`；确认 JAR 中 `YamlEncryptor`、`SQLiteHelper` 的实现。
2. 从 `YamlEncryptor` 提取硬编码种子字符串，计算 `SHA1(seed)[:16]` 作为 AES-128 key；Base64 解码 version.txt，AES-ECB 解密并去 PKCS5/7 padding。
3. 解析 JSON，记录 `servers`、`upgradeUrl`、`jarLibs`、`licenseKey`、`version`、`overTime`、`serverPath`。
4. 从 `SQLiteHelper` 提取 H2 的 `LAUNCHER` 密码；用 H2 工具连接 `agent.mv.db`，查询 `setting` 表及历史行。
5. 对比 version.txt 与 DB 中的 C2/版本/时间差异，整理 IOC（IP、URL、licenseKey、插件文件名、路径）。
6. 检查 `plugins` 目录下的 `proxy-agent.jar`、`lib-agent.jar`、`xjar-pscp.exe` 等插件，确认是否被篡改/替换。

## PoC

```python
import base64, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

SEED = "<YamlEncryptor 中的硬编码字符串>"
key = hashlib.sha1(SEED.encode()).digest()[:16]

ct = base64.b64decode(open("plugins/version.txt").read().strip())
pt = unpad(AES.new(key, AES.MODE_ECB).decrypt(ct), 16)
print(pt.decode())
```

H2 连接（示意）：

```text
jdbc:h2:file:./plugins/data/agent.mv.db;USER=LAUNCHER;PASSWORD=<SQLiteHelper 中的口令>
SELECT * FROM setting;
```

## 变体与关联

- **加密变体**：AES-ECB/CBC、Base64/hex、SHA1/MD5/PBKDF2 派生、硬编码 key 或从机器信息派生。
- **存储变体**：version.txt、JSON/YAML、SQLite/H2/Derby、注册表、环境变量；多份配置可能不一致。
- **远控变体**：Java RAT、Cobalt Strike 配置、Remcos/AsyncRAT 设置；思路都是找硬编码 key/口令并解析配置。
- **关联**：[[code-analysis-reverse-unpacking-xjar-encrypted-class-heap-key]]（先解 XJar 才能看到 YamlEncryptor/SQLiteHelper）；[[defense-forensics-java-rat-plugin-loader-neutrino-tunnel]]（配置中的插件/隧道能力）；[[code-analysis-reverse-windows-remcos-settings-config-extraction]]（Remcos 配置提取的同类思路）。
- **边界**：key 由远程下发/硬件绑定、配置使用非对称加密、DB 口令随机化时，需要动态调试/内存取证。

## 检测与防御

- **检测**：样本目录出现 `version.txt`、`agent.mv.db`、`plugins`、`proxy-agent.jar`、`lib-agent.jar`、`xjar-pscp.exe`；H2 数据库用户 `LAUNCHER`；进程访问 `C:\ClientManager_PSC`；外连 `:9010/version/update`。
- **防御**：阻断 C2/升级 URL 与相关 IP；监控 `plugins` 目录与 H2 文件创建；对 Java 进程加载未知 JAR/插件告警。
- **取证**：保留 version.txt/agent.mv.db 原始哈希；解密结果只读保存；关联进程、网络、文件时间线。
- **合规**：仅用于授权 malware 分析与取证。
