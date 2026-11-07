---
id: web-nodejs-prototype-pollution-n8n-node-params-object-assign
title: n8n XML/GSuiteAdmin 节点参数原型污染（CVE-2026-33696）：工作流作者注入 __proto__ 并声称升级 RCE
type: scenario
domain: web
path: web/nodejs/prototype-pollution
technique: n8n-node-parameter-object-assign-prototype-pollution
aliases:
- n8n 原型链污染
- CVE-2026-33696
- n8n XML 节点原型污染
- n8n GSuiteAdmin 原型污染
- Object.assign __proto__
- n8n RCE
tags:
- n8n
- nodejs
- prototype-pollution
- object-assign
- workflow
- rce
- cve-2026-33696
cve:
- CVE-2026-33696
severity: high
confidence: medium
status: verified
affected_versions: < 2.14.1、< 2.13.3、< 1.123.27（三条发布线；修复于对应版本）
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V132
  verified_at: '2026-11-06T05:49:19+08:00'
  notes: 已对照原文及4张图核对：CVE-2026-33696 版本区间、XML/GSuiteAdmin Object.assign 入口与代码一致；原文未展示从局部原型污染到 Object.prototype 全局污染及 RCE 的完整 gadget，卡片已如实标注，RCE 危害依据官方通告而非文中 PoC。
---

## 一句话结论

n8n 在 2.14.1、2.13.3、1.123.27 之前，拥有创建/修改工作流权限的已认证用户可以在 XML 节点的 `options` 或 GSuiteAdmin 节点的 `additionalFields`/`options`/`updateFields` 中塞入带自有 `__proto__` 键的 JSON，经 `Object.assign` 触发原型污染；官方通告称可进一步在 n8n 实例上执行远程代码（CVE-2026-33696，CVSS 9.4）。

## 原理

- **入口是节点参数**：n8n 工作流作者可以任意设置节点参数。`getNodeParameter('options', ...)` / `getNodeParameter('additionalFields', ...)` 返回的对象来自工作流 JSON，攻击者可以让它带有一个自有的可枚举键 `__proto__`（`JSON.parse` 会产生自有键，而 JS 对象字面量 `{__proto__: ...}` 是设置原型、不是自有键）。
- **XML 节点**：`const parserOptions = Object.assign({ mergeAttrs: true, explicitArray: false }, options);`。`Object.assign` 遍历 `options` 的自有可枚举属性并写入 target；遇到 `__proto__` 键时触发原型 setter，target 的原型被替换为攻击者提供的对象。
- **GSuiteAdmin 节点**：多处 `Object.assign(body, additionalFields)`、`Object.assign(qs, options)`、`Object.assign(body, updateFields)`，其中 `body` 常是 `{ email }` 之类的普通对象，`additionalFields = { "__proto__": { "isAdmin": true } }` 会把 `body` 的原型指向攻击者对象，后续字段读取/合并可能继承该属性。
- **从局部原型到全局污染**：需要说明的是，标准 ECMAScript 语义下 `Object.assign(target, source)` 对 `target["__proto__"]` 的赋值只改变 `target` 的原型，并不会直接改写 `Object.prototype`；要形成「所有普通对象都继承该属性」的全局污染，还需要污染对象在后续被并入共享配置/原型，或 sink 直接把属性写到 `Object.prototype`。原文断言可写入 `Object.prototype` 并升级 RCE，但未展示这条下游 gadget 的具体代码。
- **为什么能升级 RCE**：Node.js 原型污染常见的 RCE 路径包括污染 `NODE_OPTIONS=-r <文件>` 让子进程预加载模块、污染 `child_process` 的 `env`/`shell` 选项、或污染未声明标识符后经 `Function(query)(query)` 执行；n8n 作为工作流平台会启动子进程/执行表达式，具备这类 gadget 的环境。

## 触发条件

- n8n 版本低于 2.14.1、2.13.3 或 1.123.27。
- 攻击者拥有创建/修改工作流权限的已认证账号。
- 工作流使用了 XML 节点（`xmlToJson` 模式的 `options`）或 GSuiteAdmin 节点（`additionalFields`、`options`、`updateFields`）。
- 节点参数校验没有拒绝 `__proto__`/`constructor`/`prototype` 等键。
- 目标进程存在可利用的下游 gadget（子进程环境变量、动态执行等），且未被容器/权限策略限制。

## 利用步骤

1. 登录 n8n，确认版本低于修复版本，并确认账号可创建/编辑工作流。
2. 新建工作流，加入 XML 节点（或 GSuiteAdmin 节点），把 `options`/`additionalFields` 设置为带 `__proto__` 的 JSON。
3. 运行工作流，观察目标对象是否继承了污染属性；可用唯一标记属性（如 `polluted`）验证。
4. 若 `__proto__` 被过滤，尝试 `constructor.prototype` 等绕过形式。
5. 根据目标进程的 gadget 构造 RCE：例如让子进程继承被污染的 `NODE_OPTIONS`，或让动态执行路径读取被污染的函数/参数。原文未给出该步的完整 payload。
6. 若无法升级 RCE，至少可造成节点行为/鉴权判断被污染属性影响。

## PoC

原文未给出可直接执行的完整 RCE PoC。按文中入口可构造的最小参数示例（未在目标环境执行）：

```json
{
  "options": {
    "__proto__": {
      "polluted": true
    }
  }
}
```

GSuiteAdmin 变体：

```json
{
  "additionalFields": {
    "__proto__": {
      "isAdmin": true
    }
  }
}
```

用 Node 验证 `Object.assign` 语义的片段（说明局部原型变化与全局污染的区别）：

```javascript
const src = JSON.parse('{"__proto__":{"polluted":true}}');
const target = Object.assign({ mergeAttrs: true }, src);
console.log(target.polluted);            // true：target 的原型被替换
console.log({}.polluted);                // undefined：Object.prototype 未被直接改写
```

## 变体与关联

- **绕过变体**：若 `__proto__` 被过滤，使用 `constructor.prototype`、嵌套键、Unicode 转义等；参见 [[web-nodejs-prototype-pollution-filter-bypass]]。
- **深合并变体**：JSON 自有 `__proto__` 进入递归 merge 时会直接落到 `Object.prototype`；参见 [[web-nodejs-prototype-pollution-merge-json-parse]]。
- **RCE gadget**：[[web-nodejs-prototype-pollution-node-options-preload-rce]]（污染 `NODE_OPTIONS=-r` 让 node 子进程预加载）、[[web-nodejs-prototype-pollution-undeclared-identifier-function-rce]]（污染未声明标识符经 `Function(query)(query)` 执行）。
- **n8n 其他利用面**：[[web-nodejs-n8n-authenticated-execute-command-workflow-rce]]（后台 Execute Command 节点直接命令执行）、[[web-nodejs-n8n-expression-sandbox-escape-rce]]（表达式沙箱逃逸）。
- **边界**：若 n8n 已升级、节点参数 schema 拒绝危险键、或进程无子进程/动态执行 gadget，RCE 不成立。

## 检测与防御

- **升级**：升级到 2.14.1、2.13.3、1.123.27 或更高版本。
- **临时缓解**：把工作流创建/编辑权限限制为完全可信用户；将 `n8n-nodes-base.xml` 加入 `NODES_EXCLUDE` 环境变量禁用 XML 节点（官方说明该措施不能完全消除风险）。
- **参数校验**：对节点参数做 schema 校验，拒绝 `__proto__`、`constructor`、`prototype` 等键；使用 `Object.create(null)` 或 `Map` 承载不可信键值。
- **运行时加固**：冻结 `Object.prototype`；限制 n8n 子进程环境变量与动态执行能力；容器化并最小权限运行。
- **检测信号**：工作流 JSON 中出现 `__proto__`/`constructor/prototype` 键；节点参数包含异常 `isAdmin`、`NODE_OPTIONS`、`shell` 等属性；n8n 进程启动异常子进程或加载非预期模块。
