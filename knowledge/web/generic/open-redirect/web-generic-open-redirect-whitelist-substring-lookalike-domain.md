---
id: web-generic-open-redirect-whitelist-substring-lookalike-domain
title: 开放重定向白名单子串缺陷：校验只判断“包含 victim.com”，注册 testvictim.com 类形似域即可通过
type: scenario
domain: web
path: web/generic/open-redirect
technique: redirect-whitelist-substring-lookalike-domain
aliases:
- 白名单包含绕过
- 形似域名
- testaaa.com 绕过
- 域名包含判断缺陷
- lookalike domain redirect
tags:
- open-redirect
- whitelist
- substring
- lookalike-domain
- phishing
- web
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V445
  verified_at: '2026-11-09T23:29:52+08:00'
  notes: 已对照原文『利用白名单缺陷绕过』段落核对：白名单只判断字符串包含 aaa.com、注册 testaaa.com 形似域即可通过，以及把白名单域放到 path/query/子域的思路均一致；PoC 与修复建议（host 精确匹配或带点边界后缀）正确。未验证点：未实测具体站点，原文未给真实案例域名；无组件版本。与 URL 解析歧义卡为不同缺陷（contains 逻辑缺陷 vs 解析器差异），已在两卡互链。
---

## 一句话结论

如果跳转白名单用“url 里包含公司域名 aaa.com”来判断是否合法，攻击者只需注册 `testaaa.com`（或把白名单域放在 `attacker.com` 的路径/子域里）就能让字符串包含检查通过，而浏览器实际访问的是攻击者控制的域名；这是域名校验写成子串匹配而非 host 精确比较的典型逻辑缺陷。

## 原理

- 典型错误实现：`if ("aaa.com" in target) { redirect(target) }`、`target.indexOf("aaa.com") !== -1`、或黑名单式 `if (!target.includes("evil.com"))`。
- 字符串包含不等于域名归属：`http://testaaa.com`、`http://aaa.com.attacker.com`、`http://attacker.com/aaa.com`、`http://attacker.com?aaa.com`、`http://attacker.com#aaa.com` 都包含 `aaa.com`，但 host 分别是 `testaaa.com`、`aaa.com.attacker.com`、`attacker.com`。
- 攻击者只需要注册/控制其中一种形态（如 `testaaa.com`）即可；如果白名单限制为“包含任意子域”，甚至可以在自己的域名前拼接公司品牌，形成高度可信的钓鱼 URL：`https://login.aaa.com.testaaa.com`。
- 为什么有效：校验器把“字符串中出现公司域”当成“目标是公司域”；浏览器按 host 解析，域名注册规则按 label 从右向左匹配，`testaaa.com` 与 `aaa.com` 是完全不同的注册域。
- 该缺陷常与 `@`、`#`、路径拼接等技巧叠加：即使实现改用“前缀匹配”，把白名单域放到 `@` 前或路径中仍可能绕过（见 URL 解析歧义卡）。

## 触发条件

- 跳转参数存在白名单校验，且校验使用 contains/indexOf/简单正则（未锚定 host 边界）；
- 攻击者能注册/控制包含白名单域字符串的域名（`testaaa.com`、`aaa-cdn.com` 等），或白名单域允许出现在子域位置；
- 浏览器会按 host 访问攻击者域（`@`/路径变体在部分浏览器会提示）。

## 利用步骤

1. 用正常白名单域测试跳转，观察被拒绝时返回的错误；尝试在合法域后追加不存在路径/查询，判断校验是前缀、包含还是 host 精确匹配。
2. 构造包含白名单字符串的形似域（如白名单为 `aaa.com` → 注册 `testaaa.com`、`aaa.com.evil.com`），或把白名单域放进攻击者 URL 的 path/query/fragment。
3. 将构造值放入跳转参数，确认服务端返回的 `Location` 指向攻击者域且浏览器实际跳转成功。
4. 在攻击者域部署与目标登录页相似的页面进行钓鱼；如需绕过邮件网关，可使用形似子域 `login.aaa.com.evil.com`。

## PoC

```text
白名单判断（错误示例）:
  if ("aaa.com" in target_url): redirect(target_url)

绕过值:
  http://testaaa.com                      # 注册含 aaa.com 的域名
  http://aaa.com.attacker.com             # 白名单域作子域
  http://attacker.com/aaa.com             # 白名单域作路径
  http://attacker.com?aaa.com             # query
  http://attacker.com#aaa.com             # fragment
  http://login.aaa.com@attacker.com       # userinfo 混淆（见解析歧义卡）
```

说明：原文以 `testaaa.com` 为例，强调白名单“只检查是否包含 aaa.com，没有检查完整域名”。

## 变体与关联

- 变体：白名单是后缀检查但未加 `.` 边界：`evilaexample.com` 可绕过 `endswith("example.com")` 的变体；正确写法应为 `host == "example.com" or host.endswith(".example.com")`。
- 变体：黑名单只拦已知恶意域，攻击者注册新域即可绕过；黑名单永远不如白名单。
- 关联：URL 解析歧义绕过见 [[web-generic-open-redirect-url-parser-confusion-bypass]]；同目录信任链/嵌套跳转见 [[web-generic-open-redirect-nested-trusted-chain-bypass]]。
- 关联：域名白名单包含缺陷在认证场景的同类问题见 [[web-generic-auth-hanvon-eface-whitelist-contains-semicolon-path-bypass]]（启示：contains 校验普遍不可靠）。

## 检测与防御

- 白名单必须解析 URL 后对 host 做精确匹配或带点边界的子域匹配（`host == domain || host.endswith("." + domain)`），禁止 contains/indexOf/裸 endswith。
- 校验 scheme 与 port，拒绝 userinfo 和非标准编码；对最终 `Location` 再校验一次。
- 检测：审计代码中的 `contains/IndexOf/endswith` 跳转判断；日志中跳转目标 host 与白名单域相似但不相等（编辑距离/包含关系）时告警。
-  phishing 监测：对包含公司品牌但注册域不同的域名做证书透明/新注册域监控。
