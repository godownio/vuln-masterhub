---
id: cloud-container-image-config-history-secret-leak
title: 镜像 config/history 泄露构建期凭据：crane config / docker history 中的 RUN 参数、ARG 与环境变量
type: scenario
domain: cloud
path: cloud/container
technique: oci-image-history-secret-leak
tags:
- container
- image
- docker
- registry
- credential
- supply-chain
- build-args
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V623
  verified_at: '2026-11-12T22:04:03+08:00'
  notes: 已对照原文与全部14张截图核对：本题（Challenge 3 Image Inquisition）图02 显示无凭据 crane config 401，图03 从 IMDS 读取节点角色临时凭据，图04 用 aws ecr get-login-password + crane auth login 后 crane config 的 history.created_by 中直接出现 ARTIFACTORY_USERNAME/ARTIFACTORY_TOKEN=wiz_eks_challenge{the_history_of_container_images_could_reveal_the_secrets_to_the_future}/ARTIFACTORY_REPO，与卡片'构建历史泄露凭据'结论一致。卡片为镜像 config/history 元数据泄露的原子场景，与 cloud-container-docker-registry-v2-unauth-catalog-image-secret-dump（未授权 registry + 层内文件）和 pentest-recon-github-repo-history-secret-mining（GitHub 仓库历史）均非同链；dedup 报告 recommendation=new、0 duplicate，dup-scan 无本篇配对。修正：原文关联链接 cloud-k8s-imagepullsecrets-dockerconfigjson-credential-theft 在库中不存在，已改为已存在的 cloud-k8s-k8s-rbac-secret-read（imagePullSecrets 读取场景）。无 CVE/affected_versions，保持为空。未在真实环境复现。
url: /docs/cloud/container/cloud-container-image-config-history-secret-leak/
draft: false
kb_aliases:
- 镜像历史泄露密钥
- docker history 泄露 token
- crane config history
- 构建参数写入镜像历史
- ARG 泄露凭据
---

## 一句话结论

只要对镜像有 pull 权限，`crane config`/`docker history --no-trunc` 就能读到镜像的构建历史：直接写在 `RUN` 命令、`ARG` 展开或环境变量里的 token、密码、内部仓库地址会原样保留在 OCI config 的 `history[].created_by` 中——攻击者无需运行镜像即可从元数据里拿凭据。

## 原理

- OCI/Docker 镜像由 manifest + config + layers 组成；config 中的 `history` 数组记录每一层对应的构建命令（`created_by`），BuildKit/Dockerfile 的 `RUN`、`COPY`、`ARG` 处理命令都会写入，且 `docker history --no-trunc` 可看到完整命令。
- `ARG`/`ENV` 若在 `RUN` 中被引用（例如 `RUN pip install --index-url https://$USER:$TOKEN@internal.repo`），展开后的实际命令会进入 `created_by`；即使该环境变量没有保留在最终镜像的 `Config.Env`，历史里依然可见。
- BuildKit 的 `RUN sh -c #ARG=... ARTIFACTORY_TOKEN=...` 形式（构建参数内联到命令）同样写入历史。
- 镜像 config 是仓库的公开元数据：只要凭据允许 pull，就能 `crane config <image>` 而无需拉取全部层；因此凭据泄露不依赖解包镜像。
- 若秘密在层文件里（如 `.npmrc`、`.pip.conf`、私钥），删除发生在后续层也不安全——旧层仍可下载；OCI whiteout 只影响联合文件系统视图。

## 触发条件

- 攻击者已获得目标镜像仓库的 pull 凭据（imagePullSecrets 窃取、IMDS/ECR 角色、匿名公开仓库等）。
- 镜像构建时把凭据作为 `ARG`/`ENV` 用在 `RUN` 中，或把含秘密的文件打进层后删除。
- 仓库可访问且镜像 manifest/config 可读（大多数私有仓库默认允许 pull 凭据读取 config）。

## 利用步骤

1. 登录仓库（crane auth login / docker login）。
2. 读取镜像 config：
   `crane config <repo>/<image>:<tag> | jq '.history[].created_by'`、`docker history --no-trunc <image>`。
3. 在 `created_by` 中搜索 `token`、`password`、`AKIA`、`http://user:pass@`、内部仓库地址、`ARG` 展开串。
4. 若需要层内文件：`crane export <image> - | tar -x` 或逐层下载后检索 `.npmrc`、`.pip.conf`、`.git-credentials`、私钥等；对已删除文件按 whiteout 记录回溯旧层。
5. 用拿到的凭据访问内部制品库、云 API 或源码仓库，继续横向。

## PoC

```bash
# 只看构建历史（无需拉取层）
crane config 688655246681.dkr.ecr.us-west-1.amazonaws.com/central_repo-aaf4a7c@sha256:<digest> \
  | jq -r '.history[].created_by' | grep -iE 'token|pass|key|user'

# 输出可能形如：
# RUN sh -c #ARTIFACTORY_USERNAME=challenge@example.com ARTIFACTORY_TOKEN=<secret> \
#   ARTIFACTORY_REPO=base_repo /bin/sh -c pip install setuptools --index-url intrepo.example.com

# 传统 docker 客户端
docker history --no-trunc <image>

# 层内文件检索
crane export <image> - | tar -x -C /tmp/img && grep -rEi 'token|password' /tmp/img
```

## 变体与关联

- 变体：秘密写在 `ENV`/`LABEL`/`ONBUILD` 指令中，直接保留在 `Config.Env`/`Config.Labels` 里；`crane config` 可读。
- 变体：多阶段构建里前一阶段含秘密且未被真正丢弃时，层仍可下载；`docker build --secret` 是正确做法。
- 关联：[[cloud-k8s-k8s-rbac-secret-read]]（get/list secrets 读取 imagePullSecrets 是获得 pull 凭据的前一步）、[[cloud-container-oci-whiteout-deleted-file-recovery]]（删除文件仍可从层恢复）、[[cloud-container-registry-polling-image-tag-repoison-escape]]（有 push 权限时的后续利用）。
- 边界：镜像由 `docker build --secret`/BuildKit secret mount 注入且未展开到命令行时，历史中不会出现明文；config 被仓库策略屏蔽时需改用 manifest/层分析。

## 检测与防御

- 构建：禁止把凭据写进 `ARG`/`ENV`/`RUN`，改用 BuildKit `--secret` 挂载；CI 变量脱敏；构建后扫描 config/history。
- 仓库：对镜像 config 与历史做秘密扫描（含历史层），发布前阻断命中；限制 pull 权限范围。
- 响应：轮换泄露的 token，检查制品库访问日志；对已发布镜像删除并重建，注意旧 digest 仍可能被缓存。
- 检测：构建日志与镜像历史中出现 token 模式；仓库侧对同一凭据的异常 pull/config 读取。
