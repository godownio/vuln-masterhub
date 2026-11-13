---
id: web-generic-sqli-nosql-document-mass-assignment
title: NoSQL 文档整包落库的批量赋值：更新/新增接口未做字段白名单，注入 level/role/create_time 污染数据
type: scenario
domain: web
path: web/generic/sqli
technique: nosql-document-mass-assignment
aliases:
- NoSQL 批量赋值
- 文档整包更新
- 字段污染
- level/role 注入
- create_time 篡改
- 无模式数据库提权
tags:
- nosql
- mongodb
- mass-assignment
- parameter-binding
- privilege-escalation
- data-integrity
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V482
  verified_at: '2026-11-10T21:25:59+08:00'
  notes: 已对照原文与31张图核对：伪代码 db.user.update(user_data[id], user_data) 与正常/攻击请求 {"phonenum":...,"level":1,"role":"admin"} 与原文一致；实测截图（图25-30）额外字段 wz、laotie、嵌套 xxx:{yyy:zzz} 与 create_time=-1 均落入文档，新增业务接口同样整包落库，卡内描述与图文一致；$set/$unset 作为更进一步风险已标注'视解析与过滤情况'。与 Spring @RequestBody/roleId 参数篡改卡为不同数据层原子，dedup top候选 new，非重复。原文未标组件/数据库版本，affected_versions 留空正确。未验证点：level/role 为原文文字示例，实测截图落库字段为 wz/laotie/xxx/create_time，卡片已把两类并列说明；未在本机复跑。frontmatter 无 sources/source_url。
---

## 一句话结论

更新/新增接口把客户端提交的整个 JSON 对象直接当作 NoSQL 文档（`db.user.update(user_data[id], user_data)`、`insert(user_data)`），不做字段白名单；攻击者在正常资料字段之外追加 `level`、`role`、`create_time`、嵌套对象等任意键，就会被原样写入文档，实现权限提升、时间戳伪造与数据污染。

## 原理

- **无模式存储接受任意键**：MongoDB 等文档数据库不需要固定 schema，`update`/`insert` 传入的文档里出现新字段会直接落库；后端如果直接把请求体当文档，就把“客户端可写字段集合”扩大到“任意字段”。
- **典型伪代码**：

  ```python
  user_data = POST.data
  db.user.update(user_data['id'], user_data)
  ```

  正常请求 `{"phonenum":"13344445555","age":18}`；攻击者请求 `{"phonenum":"...","age":18,"level":1,"role":"admin"}`，多出的 `level`/`role` 随对象一起写入。
- **示例系统的实测表现**：
  - 编辑接口提交额外字段后，数据库文档中出现 `wz`、`laotie`、`xxx:{yyy:"zzz"}` 等原本不存在的字段（含嵌套对象）。
  - `create_time` 被直接改成 `-1`，说明服务端没有保护内部/审计字段。
  - 新增业务接口同样把整包 JSON 落库，造成“污染数据库”。
- **为什么能提权**：业务后续读取 `role`/`level`/`status` 等字段做权限判断；一旦攻击者能写这些字段，就等于自己给自己授权（与 SQL 时代的 mass assignment 相同，但 NoSQL 没有 schema 约束，更容易被忽略）。
- **与操作符注入的关系**：如果更新文档允许 `$` 开头键，攻击者还可能提交 `{"$set":{"role":"admin"}}`、`{"$unset":{...}}` 等更新操作符，修改未在表单中暴露的字段；本卡聚焦“额外字段整包落库”，操作符注入属于更进一步的风险。

## 触发条件

- 更新/新增接口使用自动绑定或直接把请求体 JSON 作为文档传入 NoSQL 写入。
- 没有服务端 DTO/字段白名单，也没有过滤 `$` 开头键。
- 攻击者拥有可调用该接口的普通账号（注册/登录即可），或接口本身未授权。
- 业务权限判断依赖文档中的 `role`/`level`/`status` 等可写字段。

## 利用步骤

1. 抓取资料编辑/新增请求，确认服务端接受 JSON 且返回成功。
2. 保留正常字段，追加 `"level":1`、`"role":"admin"`、`"isAdmin":true` 等候选字段，观察返回与页面表现。
3. 读取资料/重新登录或访问高权限接口，确认字段是否生效；必要时逐字段试探。
4. 追加 `"create_time":-1` 或修改 `update_time`，验证内部字段是否被接受。
5. 提交嵌套对象/数组（如 `"xxx":{"yyy":"zzz"}`），确认服务端不做结构校验。
6. 若字段生效，进一步尝试 `$set`/`$unset` 等操作符键（视解析与过滤情况）。

## PoC

正常请求：

```json
{"phonenum":"13344445555","age":18}
```

污染请求：

```json
{"phonenum":"13344445555","age":18,"level":1,"role":"admin","create_time":-1,"xxx":{"yyy":"zzz"}}
```

示例系统中额外字段与 `create_time=-1` 均出现在数据库文档中；新增接口提交同类 JSON 也会整包落库。

## 变体与关联

- **变体**：`$set`/`$unset`/`$inc` 操作符键注入（可修改未暴露字段）；数组/嵌套对象污染；批量更新接口一次污染多条记录。
- 关联：[[web-java-framework-spring-requestbody-mass-assignment-privilege-escalation]]（Spring @RequestBody 批量赋值）、[[web-generic-auth-roleid-roleids-parameter-tampering-admin]]（角色参数篡改）、[[web-nodejs-merge-proto-filter-mass-assignment-isadmin]]（Node 合并/过滤绕过）、[[web-generic-sqli-php-array-parameter-mongodb-operator-injection]]（同一 NoSQL 上下文中的操作符注入）。
- 边界：后端使用 DTO/白名单、显式字段赋值、schema 校验或拒绝未知键时，不成立；若数据库层有字段级权限/触发器，也可能阻断。

## 检测与防御

- **代码层**：写入前用 DTO/允许字段列表重建文档，禁止把请求体整体传入 `update`/`insert`；过滤 `$` 开头键；对 `role`/`level`/`create_time` 等敏感字段服务端强制赋值。
- **数据库层**：为应用账号配置最小权限，限制可写集合与字段；开启 schema validation（MongoDB `$jsonSchema`）校验文档结构。
- **检测信号**：更新请求中出现业务表单之外的字段名（level/role/isAdmin/create_time）；文档字段数量或结构异常变化；普通用户文档出现管理员标记；`$set`/`$unset` 出现在请求体键中。
