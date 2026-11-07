---
id: ai-security-supply-chain-aws-toolkit-release-build-curl-overwrite
title: AI IDE 扩展打包期投毒：package.ts 释放钩子 curl 覆盖扩展入口（CVE-2025-8217）
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: ai-ide-extension-release-build-curl-overwrite
tags:
- ai-security
- supply-chain
- vscode
- aws-toolkit
- cve-2025-8217
- release-poisoning
- build-hook
cve:
- CVE-2025-8217
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T09:51:04+08:00'
  notes: 已对照原文 AS4 节与图 16/18 核对：package.ts 的 isCurlAvailable/downloadFiles、platform()!=='linux' 返回、curl --version 检查、process.cwd() 含 amazonq 条件、远程 extensionNode.bk 覆盖 src/extensionNode.ts、无 hash 校验、因语法错误未影响生产，均与原文一致；CVE-2025-8217 与 AWS-2025-015 对齐。未验证点：PoC 为片段示意未复跑；原文未给完整恶意代码与版本区间（不猜版本）；frontmatter 无 sources/source_url。
url: /docs/ai-security/supply-chain/ai-security-supply-chain-aws-toolkit-release-build-curl-overwrite/
draft: false
kb_aliases:
- CVE-2025-8217
- AWS Toolkit VSCode 投毒
- 打包期钩子
- extensionNode.ts 覆盖
- release build poisoning
---

## 一句话结论

攻击者在 AI IDE 扩展的 `scripts/package.ts` 中植入打包期钩子：当工作目录包含 `amazonq`、平台为 Linux 且存在 `curl` 时，从远程下载 `extensionNode.bk` 覆盖 `src/extensionNode.ts`，再写入打包目录覆盖扩展入口，且没有 hash/签名校验；这是 CVE-2025-8217 的供应链投毒路径，本次因语法错误未影响生产。

## 原理

- **打包脚本在发布流水线中执行**：VS Code 扩展通常用 `vsce`/自定义 `package.ts` 打包；CI 以维护者权限运行 `npm install`、`npm run package`，脚本可读写仓库与产物。
- **恶意钩子**：攻击者提交的 `package.ts` 增加 `isCurlAvailable()` 与 `downloadFiles()`：
  - 检查 `process.cwd()` 是否包含 `amazonq`（确认是目标扩展的打包目录）；
  - 检查 `platform() === 'linux'`（CI 环境）；
  - 检查 `curl --version` 可用；
  - 访问远程 URL 下载 `extensionNode.bk`，写入 `src/extensionNode.ts`；
  - 在打包目录中覆盖扩展入口文件。
- **为什么能投毒**：构建过程信任仓库里的脚本，没有对生成/覆盖的入口文件做 hash 或签名校验；恶意代码随 release 产物进入市场，用户安装/更新后即执行。这是“构建期供应链”而非运行时漏洞。
- **本次结果**：原文称恶意代码存在语法错误，最终未对生产环境造成影响，但完整展示了真实环境下 Agentic/IDE 扩展供应链的风险；CVE-2025-8217 与 AWS 安全公告 AWS-2025-015 对应此事件。
- **边界**：需要攻击者能向目标仓库提交代码并被合并/进入发布分支，或能篡改构建脚本/CI；发布流水线需有网络访问和 curl；若构建在无网络沙箱、产物签名校验严格，则链路中断。

## 触发条件

- 目标为 VS Code/AI IDE 扩展项目，发布流水线执行仓库内的 `package.ts` 或类似构建脚本。
- CI 以高权限运行，允许出站网络与 `curl`；构建产物未做签名/哈希校验。
- 攻击者可提交 PR/commit 到发布分支，或能篡改构建脚本/依赖。
- 扩展通过市场自动更新，用户安装后执行入口文件。

## 利用步骤

1. 在 `scripts/package.ts` 中加入环境判断与下载逻辑（伪装成“下载辅助文件/生成入口”的正常构建步骤）。
2. 让 `downloadFiles()` 从攻击者控制的 URL 拉取 `extensionNode.bk`，写入 `src/extensionNode.ts`。
3. 在打包目录中覆盖扩展入口文件，确保 VSIX 中包含恶意入口。
4. 触发 release 构建（合并到发布分支/打 tag），CI 执行脚本并生成带毒产物。
5. 发布到市场，用户安装/更新后执行恶意入口；攻击者可进一步窃取凭据、植入后门。
6. 授权测试应在隔离仓库/CI 中进行，使用无害的 `echo`/测试文件替代真实 payload。

## PoC

```ts
// 原文 scripts/package.ts 中出现的危险模式（示意，未完整还原）
function isCurlAvailable(): boolean {
  try {
    child_process.execFileSync('curl', ['--version']);
    return true;
  } catch {
    return false;
  }
}

function downloadFiles(urls: string[], outputDir: string, outputFile: string): void {
  if (platform() !== 'linux') return;
  if (!isCurlAvailable()) return;
  // curl 下载远程文件 -> 写入 outputDir/outputFile（可覆盖入口文件）
}
```

```text
# 攻击者远程文件（示意）
https://raw.githubusercontent.com/<attacker>/<repo>/scripts/extensionNode.bk
# 构建时被写入 src/extensionNode.ts，并覆盖打包目录入口
```

说明：原文只展示 `package.ts` 的片段与目录结构，未给出完整恶意文件；PoC 为危险模式示意，未在本机复跑。该事件最终因语法错误未影响生产。

## 变体与关联

- **npm 生命周期**：`preinstall`/`postinstall`/`prepare` 脚本在安装时执行，绕过对运行时代码的审查。
- **构建产物覆盖**：`postbuild` 脚本替换 `dist/`/`out/` 入口、sourcemap 或 `package.json` 的 `main`。
- **CI 缓存/依赖投毒**：污染构建缓存、私有 registry、GitHub Actions artifact。
- **VSIX 重打包**：攻击者获取/篡改 VSIX 后重新签名或利用市场更新通道。
- **关联**：[[ai-security-supply-chain-npm-preinstall-worm-ai-ide-persistence]]（npm 生命周期 + AI IDE 持久化）、[[ai-security-supply-chain-litellm-pypi-pth-stealer-k8s-backdoor]]（安装即执行）、[[ai-security-supply-chain-agent-skill-external-second-stage-loader]]（构建/运行时远程二阶段）。

## 检测与防御

- **构建脚本审计**：对 `package.ts`、`postinstall`、`prepublish` 等构建/安装脚本做代码审查与 diff 告警；禁止在构建脚本中无条件下载远程文件。
- **构建沙箱**：CI 构建在无网络或允许列表网络中运行，限制 `curl`/`wget` 出站；构建产物生成后计算 hash 并签名。
- **产物校验**：发布前对比 `src/extensionNode.ts` 与产物入口的 hash，校验 VSIX 签名/SLSA provenance；用户侧只安装签名验证通过的扩展。
- **供应链监控**：监控发布分支的异常提交、CI 中的远程下载、`package.json` 的 `main`/`scripts` 变更；对扩展做 SBOM 与依赖固定。
- **响应**：发现投毒后撤回/下架版本、轮换 CI/发布凭据、通知用户回滚，并检查构建缓存与发布产物。
