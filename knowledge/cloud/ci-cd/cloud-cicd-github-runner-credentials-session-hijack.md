---
id: cloud-cicd-github-runner-credentials-session-hijack
title: 窃取自托管 runner 的 .credentials/.credentials_rsaparams/.runner：伪造 runner 客户端接管会话并解密作业消息窃取 secrets
type: scenario
domain: cloud
path: cloud/ci-cd
technique: github-runner-credentials-session-hijack
aliases:
- runner 凭据窃取
- .credentials_rsaparams
- gh-hijack-runner
- runner 会话劫持
- 删除 runner session
- 作业消息 AES 解密
tags:
- ci-cd
- github-actions
- self-hosted-runner
- credential-theft
- session-hijack
- secrets
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V343
  verified_at: '2026-11-08T22:17:44+08:00'
  notes: 已对照原文核对 .credentials/.credentials_rsaparams/.runner、_diag 会话 ID、gh-hijack-runner --delete-session-id、REPO_SECRET/SUPER_SECRET/system.github.token 输出与图08 internal error；依赖外部工具与 runner 版本，confidence medium 合理。
---

## 一句话结论

自托管 runner 的安装目录里有 `.credentials`（客户端 ID/令牌）、`.credentials_rsaparams`（RSA 私钥）和 `.runner`（runner 配置）；拿到这些文件后，攻击者可以伪造一个 GitHub Actions runner 客户端，用同一 runner 身份建立会话、解密作业消息并打印其中的 secrets；由于一个 runner 同时只维护一个会话，攻击者先用 `_diag` 日志里的会话 ID 删除合法会话，再接管作业投递。

## 原理

- **runner 凭据三件套**：`.credentials`/`.credentials_rsaparams`/`.runner` 是该 runner 的身份材料——客户端 ID、私钥与注册信息；谁持有它们，谁就能以这个 runner 的身份与 GitHub Actions 服务通信。
- **每 runner 单会话**：runner 与 GitHub 建立长轮询/消息会话，同一 runner 一次只能有一个活跃会话。要接管，需要先让合法 runner 的会话失效；会话 ID 可从 `_diag/*` 日志中的 `Message ... received from session '<uuid>'` 提取，再通过客户端 `--delete-session-id` 删除。
- **作业消息加密**：作业下发消息用会话协商的 AES 密钥加密；伪造客户端在建立会话时拿到密钥，即可解密消息体，从环境变量中读出 secrets 与 `system.github.token`。
- **为什么可复用**：这些凭据可能被备份、镜像层、员工泄露、runner 持久化磁盘或容器快照带出；攻击者不必先 RCE 目标组织，只要拿到一套有效 runner 凭据并能让合法 runner 掉线，就能接收目标 runner 的作业。
- **副作用**：删除合法会话会让合法 runner 报错/崩溃，GitHub 侧可能显示内部错误；文中脚本在拿到 secrets 后向 GitHub 返回错误，表面上只像一次普通作业失败，缺少明显「恶意 runner」痕迹。
- **边界**：runner 凭据已轮换/过期、合法 runner 离线（无需删除会话）、组织使用一次性/临时 runner、作业只允许特定 runner 组时，接管难度上升。

## 触发条件

- 攻击者获得某自托管 runner 的 `.credentials`、`.credentials_rsaparams`、`.runner` 文件（或其中足够的身份材料）。
- 该 runner 仍注册在目标组织/仓库且未轮换凭据。
- 攻击者能与 GitHub Actions 服务通信并建立 runner 会话；必要时能删除合法会话。
- 有作业会被调度到该 runner（或攻击者能等待/触发）。

## 利用步骤

1. 在失陷主机/镜像/备份中找到 runner 安装目录（如 `/actions-runner`），收集 `.credentials`、`.credentials_rsaparams`、`.runner`。
2. 从 `_diag/*` 日志提取合法会话 ID：`grep -i session _diag/*`，找到 `session '<uuid>'`。
3. 运行伪造客户端，携带 runner 凭据并指定删除该会话：
   `gh-hijack-runner.py --rsa-params credentials_rsaparams.json --credentials credentials.json --runner runner.json --delete-session-id <uuid>`。
4. 客户端建立新会话，等待作业；收到消息后解密并打印环境变量/secrets（示例 `REPO_SECRET`、`SUPER_SECRET`、`system.github.token`）。
5. 用窃取的 secrets/token 继续访问仓库、云资源或部署目标；合法 runner 因会话被删而崩溃/报错，可作为被发现线索。
6. 若无需删除会话（合法 runner 已离线），直接建立会话即可。

## PoC

```text
# runner 安装目录（示意）
/actions-runner$ ll
-rw-r--r-- .credentials          # 客户端 ID/token
-rw------- .credentials_rsaparams # RSA 私钥
-rw-r--r-- .runner               # runner 配置

# 从诊断日志取会话 ID
$ grep -i session _diag/*
[2024-04-21 18:03:46Z INFO MessageListener] Message '5' received from session 'aab007e0-eedd-4c1b-96b4-a7c2c128c31a'.

# 伪造 runner 并删除合法会话
$ gh-hijack-runner.py --rsa-params credentials_rsaparams.json \
    --credentials credentials.json --runner runner.json \
    --delete-session-id aab007e0-eedd-4c1b-96b4-a7c2c128c31a
[+] Session aab007e0-eedd-4c1b-96b4-a7c2c128c31a.
```

```text
# 另一种用法：凭据直接接管（不删除会话）
$ gh-hijack-runner.py --rsa-params credentials_rsaparams.json \
    --credentials credentials.json --runner runner.json
[+] Session ID: 3c88c6f7-...
[+] AES key: eLN3rhf3D...UHewLw==
[+] New Job: init (messageId=2)
- REPO_SECRET: repo secret
- SUPER_SECRET: super secret password
- system.github.token: ghs_RqD...
```

说明：命令与输出字段来自文中演示；工具需与目标 runner 版本兼容。

## 变体与关联

- 变体：凭据来自容器镜像层、备份、退役机器、员工设备；也可与 [[cloud-cicd-github-actions-runner-label-ubuntu-latest-hijack]] 组合（先注册恶意 runner，再长期持有凭据）。
- 变体：不删除会话，等待合法 runner 离线；或用 runner 组/仓库级注册令牌创建新 runner 身份。
- [[cloud-cicd-github-app-private-key-runner-registration-token]]：不依赖现有 runner 文件、从 App 私钥获取注册令牌的另一条路。
- [[cloud-cicd-github-actions-pr-head-ref-expression-injection-rce]]：在 runner 上获得初始 RCE、进而读取凭据文件的入口。
- 边界：凭据轮换、ephemeral runner、网络隔离、仅允许 runner 组内作业时接管失败或收益有限。

## 检测与防御

- 防御：runner 使用一次性/临时（ephemeral）模式，作业后销毁；定期轮换 runner 凭据；限制 runner 文件系统访问与备份范围；退役 runner 时从组织删除并吊销凭据。
- 防御：为 runner 配置专用低权限账号与网络出口，作业 secrets 按需注入，避免长期驻留在 runner 环境。
- 检测：同一 runner 出现重复会话/会话被删除、合法 runner 异常崩溃；`_diag` 中出现非常规客户端连接；runner 主机上出现对 `.credentials*`/`.runner` 的异常读取或外传。
- 检测：Audit Log 中 runner 会话/作业领取异常；作业失败与未知客户端会话关联；secrets 使用后出现异常仓库/云操作。
- 响应：吊销 runner 凭据并从组织移除 runner、轮换全部 secrets 与 token、排查获取凭据的初始入口与持久化。
