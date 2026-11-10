---
title: CI/CD
weight: 1
---

# CI/CD

## 这层是什么

流水线、凭据、供应链与投毒。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [CI 日志脱敏绕过：base32 不在掩码变体集合内，base64 折行反被 4 字符分组对齐规则啃成残片（Gitea 28.2.0 实测）](cloud-cicd-log-masking-bypass-base32-variant-threshold/) | verified | high | 2026-11-06 |
| [CVE-2026-33075 FastGPT：pull_request_target 检出外部 PR 代码并用攻击者 Dockerfile 构建推镜像](cloud-cicd-github-actions-pull-request-target-checkout-rce/) | verified | high | 2026-11-05 |
| [GitHub Actions 表达式注入：PR 分支名（head.ref）经 github-script 输出进入 run 脚本导致 CI 命令执行](cloud-cicd-github-actions-pr-head-ref-expression-injection-rce/) | verified | high | 2026-11-08 |
| [GitHub App 私钥泄露到 CI 环境：生成安装令牌并以 organization_self_hosted_runners:write 换取组织 runner 注册令牌](cloud-cicd-github-app-private-key-runner-registration-token/) | verified | high | 2026-11-08 |
| [GitLab OIDC 通配符信任滥用：组内任意项目 CI 作业代入 AWS 角色并窃取 S3 凭据](cloud-cicd-gitlab-oidc-wildcard-sub-aws-role-assumption/) | verified | high | 2026-11-07 |
| [Gradle Wrapper jar 供应链后门：.webp 伪装 class 自定义 ClassLoader + LLVM IR 解释器加密外传源码](cloud-cicd-gradle-wrapper-jar-backdoor-webp-classloader-llvm-vm/) | verified | medium | 2026-11-06 |
| [jlink 供应链植入：替换 java.base.jmod 在定制运行时镜像中植入 JVM 级后门](cloud-cicd-jlink-java-base-jmod-backdoor/) | verified | high | 2026-11-05 |
| [npm 依赖注入 postinstall 供应链投毒：安装即执行](cloud-cicd-npm-postinstall-supply-chain-poisoning/) | verified | high | 2026-11-05 |
| [PyPI setup.py 自定义 install 命令：安装时下载远程 Bash 脚本并 chmod 700 执行](cloud-cicd-pypi-setup-py-custom-install-command-remote-bash/) | verified | high | 2026-11-10 |
| [PyPI 包内嵌 ZIP+Base64 载荷：模块导入即解压执行，从 Dropbox 下载 WinDef.exe 木马运行](cloud-cicd-pypi-module-zip-base64-dropbox-exe/) | verified | high | 2026-11-10 |
| [PyPI 恶意包 multiplerequests：setup.py 安装期 exec base64 代码，远程两阶段拉取 CStealer 窃密后门](cloud-cicd-pypi-multiplerequests-setup-py-cstealer/) | verified | high | 2026-11-09 |
| [PyPI 恶意包导入即反弹 Shell：__init__.py 调 utils.run() 执行 Base64 载荷，C2 地址经云盘远程获取](cloud-cicd-pypi-import-base64-reverse-shell-remote-c2/) | verified | high | 2026-11-10 |
| [PyPI 拼写抢注 requests→request：克隆官方包源码植入 Cookie 外传，pip install 后静默劫持会话](cloud-cicd-pypi-typosquat-requests-cookie-exfil/) | verified | high | 2026-11-07 |
| [PyPI 拼写抢注投毒：setup.py 用 Fernet 硬编码密钥解密执行，分阶段拉取浏览器窃密与数字钱包劫持载荷](cloud-cicd-pypi-fernet-encrypted-staged-loader/) | verified | high | 2026-11-10 |
| [python-json-logger 可选依赖名被弃用后遭抢注导致安装期代码执行（CVE-2025-27607）](cloud-cicd-pypi-optional-dependency-name-takeover/) | verified | high | 2026-11-05 |
| [云利用工具投毒：仿冒 enumerate-iam 依赖 + botocore 端点劫持回传 AWS AK/SK 与 STS](cloud-cicd-accesskey-tools-typosquat-sdk-endpoint-hijack/) | verified | high | 2026-11-06 |
| [以 ubuntu-latest 标签注册恶意自托管 runner：劫持组织内 GitHub 托管作业并窃取 CI secrets](cloud-cicd-github-actions-runner-label-ubuntu-latest-hijack/) | verified | high | 2026-11-08 |
| [依赖混淆攻击：公共仓库同名高版本包劫持内部依赖并在安装/构建期执行](cloud-cicd-dependency-confusion-public-package-name-collision/) | verified | medium | 2026-11-06 |
| [恶意 Java 注解处理器经 SPI 自动加载实现编译期命令执行与反弹 Shell](cloud-cicd-java-annotation-processor-compile-rce/) | verified | high | 2026-11-05 |
| [恶意 PEP 517 构建后端在 pip 安装期执行任意代码](cloud-cicd-pep517-build-backend-install-rce/) | verified | high | 2026-11-04 |
| [托管 CI 平台作无 C2 回传信道：恶意 workflow 将 env 与 toJSON(secrets) base32 编码写入运行日志再经 API 取回](cloud-cicd-actions-log-base32-secret-exfiltration-no-c2/) | verified | high | 2026-11-06 |
| [数字钱包 Electron 客户端 app.asar 替换劫持：结束进程后用恶意 app.asar 覆盖 resources 目录](cloud-cicd-electron-wallet-app-asar-replace-hijack/) | verified | high | 2026-11-10 |
| [注解处理器 Filer API 向编译产物注入后门类](cloud-cicd-java-annotation-processor-filer-backdoor-injection/) | verified | high | 2026-11-05 |
| [窃取自托管 runner 的 .credentials/.credentials_rsaparams/.runner：伪造 runner 客户端接管会话并解密作业消息窃取 secrets](cloud-cicd-github-runner-credentials-session-hijack/) | verified | medium | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
