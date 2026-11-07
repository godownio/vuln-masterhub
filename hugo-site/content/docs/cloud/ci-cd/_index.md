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
| [GitLab OIDC 通配符信任滥用：组内任意项目 CI 作业代入 AWS 角色并窃取 S3 凭据](cloud-cicd-gitlab-oidc-wildcard-sub-aws-role-assumption/) | verified | high | 2026-11-07 |
| [Gradle Wrapper jar 供应链后门：.webp 伪装 class 自定义 ClassLoader + LLVM IR 解释器加密外传源码](cloud-cicd-gradle-wrapper-jar-backdoor-webp-classloader-llvm-vm/) | verified | medium | 2026-11-06 |
| [jlink 供应链植入：替换 java.base.jmod 在定制运行时镜像中植入 JVM 级后门](cloud-cicd-jlink-java-base-jmod-backdoor/) | verified | high | 2026-11-05 |
| [npm 依赖注入 postinstall 供应链投毒：安装即执行](cloud-cicd-npm-postinstall-supply-chain-poisoning/) | verified | high | 2026-11-05 |
| [PyPI 拼写抢注 requests→request：克隆官方包源码植入 Cookie 外传，pip install 后静默劫持会话](cloud-cicd-pypi-typosquat-requests-cookie-exfil/) | draft | high | 2026-11-07 |
| [python-json-logger 可选依赖名被弃用后遭抢注导致安装期代码执行（CVE-2025-27607）](cloud-cicd-pypi-optional-dependency-name-takeover/) | verified | high | 2026-11-05 |
| [云利用工具投毒：仿冒 enumerate-iam 依赖 + botocore 端点劫持回传 AWS AK/SK 与 STS](cloud-cicd-accesskey-tools-typosquat-sdk-endpoint-hijack/) | verified | high | 2026-11-06 |
| [依赖混淆攻击：公共仓库同名高版本包劫持内部依赖并在安装/构建期执行](cloud-cicd-dependency-confusion-public-package-name-collision/) | verified | medium | 2026-11-06 |
| [恶意 Java 注解处理器经 SPI 自动加载实现编译期命令执行与反弹 Shell](cloud-cicd-java-annotation-processor-compile-rce/) | verified | high | 2026-11-05 |
| [恶意 PEP 517 构建后端在 pip 安装期执行任意代码](cloud-cicd-pep517-build-backend-install-rce/) | verified | high | 2026-11-04 |
| [托管 CI 平台作无 C2 回传信道：恶意 workflow 将 env 与 toJSON(secrets) base32 编码写入运行日志再经 API 取回](cloud-cicd-actions-log-base32-secret-exfiltration-no-c2/) | verified | high | 2026-11-06 |
| [注解处理器 Filer API 向编译产物注入后门类](cloud-cicd-java-annotation-processor-filer-backdoor-injection/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
