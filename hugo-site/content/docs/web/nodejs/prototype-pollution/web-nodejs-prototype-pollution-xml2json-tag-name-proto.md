---
id: web-nodejs-prototype-pollution-xml2json-tag-name-proto
title: xml2json 标签名注入 __proto__：KML 解析污染 Object.prototype 并改写未声明全局变量
type: scenario
domain: web
path: web/nodejs/prototype-pollution
technique: xml2json-tag-name-proto-prototype-pollution
tags:
- nodejs
- prototype-pollution
- xml
- kml
- kmz
- xml2json
- admin-takeover
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:08:48+08:00'
  notes: 已对照原文 asystem 段核对：xml2json 以标签名建键、<__proto__ FIX_SECRET=...> 污染 Object.prototype、/admin?fix=true 依赖未声明 FIX_SECRET、KMZ PoC 均与原文一致；PoC 未本机复跑；原文未标注组件版本。
url: /docs/web/nodejs/prototype-pollution/web-nodejs-prototype-pollution-xml2json-tag-name-proto/
draft: false
kb_aliases:
- XML 标签名原型污染
- KML __proto__ 污染
- xml2json 原型链污染
- 未声明变量 FIX_SECRET
- KMZ 上传原型污染
---

## 一句话结论

Node.js 的 XML→JSON 解析器把 XML 标签名直接当作对象键写入结果时，攻击者上传含 `<__proto__ FIX_SECRET="...">` 的 KML/KMZ 即可污染 `Object.prototype`；若应用随后读取一个未声明的全局变量（如 `FIX_SECRET`），就会沿原型链取到污染值，从而重置管理员密钥或改变安全配置。

## 原理

- 常见 xml2json 实现按标签名建对象、按属性名写值：
  ```js
  if (!json[tag]) json[tag] = {};
  for (const key in attributes) json[tag][key] = attributes[key];
  ```
  当 `tag === "__proto__"` 时，`json["__proto__"]` 不是普通键，而是 `Object.prototype`；随后 `json["__proto__"]["FIX_SECRET"] = "mew2pass"` 实际执行 `Object.prototype.FIX_SECRET = "mew2pass"`。
- 在 Node/CommonJS 的非严格模式下，访问一个未声明标识符 `FIX_SECRET` 会沿作用域链找到全局对象，再沿其原型链找到 `Object.prototype.FIX_SECRET`，因此 `FIX_SECRET !== undefined` 成立。
- 若业务代码把它当作管理员密钥写入配置文件：
  ```js
  if (fix === 'true' && FIX_SECRET !== undefined) {
    fs.writeFileSync(CONFIG_PATH, String(FIX_SECRET));
    admin_secret = String(FIX_SECRET);
  }
  ```
  攻击者指定的值就成为新的管理员密钥。
- 为什么可行：解析器没有拒绝 `__proto__`/`constructor`/`prototype` 等特殊键；应用又依赖“未声明全局变量”这种隐式行为，把原型污染升级为配置篡改。
- 若解析器使用 `Object.create(null)`、显式过滤特殊键、或在严格模式下运行，该链不成立。

## 触发条件

- Node.js 应用解析用户上传的 XML/KML/KMZ，并使用把标签名/属性名直接作为对象键的解析器。
- 解析结果被用于后续业务逻辑，且代码中存在未声明变量、`obj[key]` 继承属性读取或 `in` 运算符判断等原型链敏感操作。
- 上传入口可达，且解析后的对象能影响配置/密钥/权限。
- 目标未冻结 `Object.prototype`，也未对特殊键做过滤。

## 利用步骤

1. 找到接受 `.kmz`/`.kml`/XML 的上传入口，确认后端会解析 XML 并转为 JSON。
2. 构造恶意 KML，把标签名设为 `__proto__`，属性名设为目标全局变量（如 `FIX_SECRET`），属性值为攻击者可控值。
3. 将 KML 压缩为 KMZ（或按接口要求直接上传 XML），上传触发解析。
4. 调用依赖该全局变量的管理接口（如 `/api/fix-secret`），观察是否返回成功/新密钥。
5. 用新的管理员密钥登录后台，继续利用后台功能（如模板预览 SSTI）读取敏感文件。
6. 若目标使用 `constructor.prototype` 过滤，可尝试 `constructor`、`prototype`、嵌套键或 Unicode 转义等变体。

## PoC

```xml
<?xml version="1.0" encoding="UTF-8"?>
<kml><__proto__ FIX_SECRET="mew2pass"></__proto__></kml>
```

```bash
# 压成 kmz 并上传
zip poc.kmz poc.kml
curl -F "file=@poc.kmz" -b "session=<cookie>" http://target/api/upload

# 触发依赖 FIX_SECRET 的管理接口
curl -b "session=<cookie>" http://target/api/fix-secret
# {"code":0,"data":{"admin_secret":"mew2pass"},"message":"fixed"}
```

说明：PoC 为原文流程的结构化复现，未在本机执行；仅用于授权测试。原文通过 Flask 下载接口的路径穿越先读取 Node 源码，确认 `.kmz → KML → xml2json` 与 `FIX_SECRET` 逻辑后再利用。

## 变体与关联

- 变体（特殊键）：`constructor`、`prototype`、`constructor.prototype`、嵌套 `__proto__`、Unicode 转义 `__proto__`；不同解析器的过滤点不同。
- 变体（解析器）：其他 XML→JSON、YAML→对象、表单解析器、查询字符串解析器，只要把用户可控键名写入普通对象，都可能复制该向量。
- 变体（sink）：未声明全局变量、`obj.inheritedKey`、`key in obj`、`for...in` 遍历、模板/配置合并、JWT 密钥读取。
- 关联：[[web-nodejs-prototype-pollution-undeclared-identifier-function-rce]]（原型污染控制未声明标识符的同类 sink）；[[web-nodejs-prototype-pollution-merge-json-parse]]（JSON merge 入口）；[[web-nodejs-prototype-pollution-filter-bypass]]（过滤绕过变体）。
- 边界：解析器使用 `Object.create(null)`、过滤 `__proto__`/`constructor`/`prototype`、冻结原型、严格模式或使用 `Map` 时，本链不成立。

## 检测与防御

- 检测：上传的 XML/KML 中出现 `__proto__`、`constructor`、`prototype` 标签或属性名；Node 进程中出现 `Object.prototype` 被写入非预期属性；管理接口在无正常配置变更时返回密钥被修改。
- 防御：XML→JSON 解析使用 `Object.create(null)` 或 `Map`，显式拒绝 `__proto__`/`constructor`/`prototype` 键；对解析结果做 schema 校验，只保留白名单字段。
- 加固：不要依赖未声明全局变量；使用 `const`/`let` 和严格模式；对安全配置使用不可变对象/独立存储；`Object.freeze(Object.prototype)` 作为兜底。
- 加固：上传文件做类型/内容校验，解析在低权限沙箱中进行；监控 KMZ/XML 上传与后续管理接口的异常调用链。
