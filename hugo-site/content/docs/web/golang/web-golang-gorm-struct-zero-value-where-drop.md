---
id: web-golang-gorm-struct-zero-value-where-drop
title: GORM 结构体条件零值被忽略：空 token/id 使 WHERE 条件整段丢失，查询返回首条记录
type: scenario
domain: web
path: web/golang
technique: gorm-struct-zero-value-where-condition-drop
tags:
- golang
- gorm
- orm
- zero-value
- sqli
- authz-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V518
  verified_at: '2026-11-11T13:07:37+08:00'
  notes: 已对照原文与10张截图核对：UserHandler 的 c.Query/c.GetQuery 存在性校验、UserFirst 的 DB.Where(query).First(&user) 结构体条件、?token= 返回首条用户（图01/03/04，泄露 token/username/password）、GORM 日志中 WHERE id='1' 与空值丢 WHERE 的对比（图02）均一致；卡片明确区分其非拼接注入。未验证点：PoC 未复跑；原文未给 GORM/Go 版本标记。dedup：与空参数/通配符导致查询条件塌缩等既有卡为相邻概念但根因（结构体零值忽略）不同，保留。
url: /docs/web/golang/web-golang-gorm-struct-zero-value-where-drop/
draft: false
kb_aliases:
- GORM 零值查询
- GORM Where 条件失效
- go 零值 WHERE 丢失
- token 空值越权
- First 查询返回第一条
---

## 一句话结论

GORM 用结构体作为查询条件（`db.Where(&User{Token: token}).First(&user)`）时会忽略结构体中的**零值字段**（空字符串、0、false 等）；若请求参数可为空且代码只用 `GetQuery` 判断「参数是否存在」而值允许为空，`token=""` 会让 WHERE 条件整体消失，`First` 直接返回表的第一条记录，造成越权访问/敏感信息泄露（常见于用户信息、订单等接口）。

## 原理

- **Go 零值**：Go 结构体字段未赋值时是类型零值（`string` 为 `""`、`int` 为 `0`、`bool` 为 `false`、指针为 `nil`）。语言层面无法区分「未赋值」与「显式赋值为零值」。
- **GORM 的结构体条件语义**：`Where(struct)` 只把**非零值**字段拼入 SQL 条件。`Where(&UserTab{Token: ""})` 生成的 WHERE 子句为空，等价于无条件查询；`First()` 追加 `ORDER BY <primary key> LIMIT 1`，返回第一条记录。
- **为什么参数校验挡不住**：常见写法 `token := c.Query("token"); _, exists := c.GetQuery("token"); if !exists { return 400 }` 只检查参数**是否存在**，不检查值非空；`?token=` 满足 `exists=true` 且值为 `""`，直接进入 GORM 查询。
- **危害**：返回的首条记录通常是初始管理员/种子数据，可能带 `token`、`password`、邮箱等敏感字段；同一模式在其它按字段查询的接口（`id=`、`name=`）同样成立，可横向枚举数据。
- **与 SQL 注入的区别**：这不是拼接注入，而是 ORM 条件被「合法地」丢弃，参数化后依然存在，属于业务逻辑/ORM 语义缺陷。

## 触发条件

- 后端使用 GORM（或类似「零值忽略」语义的 ORM/查询构造器）以结构体作为查询条件。
- 接口参数允许为空值（`?token=`、`{"id":""}`、`{"id":0}`），且服务端只判断参数是否存在。
- 查询使用 `First`/`Take` 且无条件兜底（无显式空值拒绝）。
- 表中有可返回的记录（通常至少一条种子数据）。

## 利用步骤

1. 审计/探测使用结构体条件查询的接口：`UserFirst(&UserTab{Token: token})`、`GetTodoById(id)` 等模式。
2. 发送空值参数：`GET /user?token=`（或 JSON `{"id":""}`），与服务端正常报错路径对比。
3. 观察响应：若返回表中第一条记录（常见为 admin，含 token/password），确认条件被丢弃。
4. 结合其它字段（`email=`、`id=`、`name=`）重复测试，扩大可枚举面；用返回的凭据/令牌尝试登录或访问其它接口。

## PoC

```go
// 有缺陷的服务端逻辑（示意）
func UserHandler(c *gin.Context) {
    token := c.Query("token")
    _, exists := c.GetQuery("token")
    if !exists {
        c.String(400, "Missing token parameter")
        return
    }
    user, err := UserFirst(&UserTab{Token: token}) // token 为空 -> WHERE 为空
    if err != nil { ... }
    c.JSON(200, gin.H{"user": user})
}

func UserFirst(query *UserTab) (*UserTab, error) {
    var user UserTab
    err := DB.Where(query).First(&user).Error
    return &user, err
}
```

```http
GET /user?token= HTTP/1.1
Host: target

HTTP/1.1 200 OK
{"user":{"ID":1,"email":"admin@example.com","token":"<leaked-token>","username":"admin","password":"<hash-or-plain>"}}
```

等价的底层 SQL 差异：

```sql
-- token 非空
SELECT * FROM user_tabs WHERE token = 'abc' ORDER BY id LIMIT 1;
-- token 为空（GORM 丢弃零值条件）
SELECT * FROM user_tabs ORDER BY id LIMIT 1;
```

## 变体与关联

- **参数类型变体**：`id=0`、`deleted=false`、`status=0` 等零值都会触发同类条件丢失；整数主键接口用 `id=` 空串时也可能被转成 0。
- **Map 条件对照**：GORM 的 `Where(map[string]interface{}{"token": token})` 会把空值拼进 SQL（`token = ''`），不会丢条件；问题专属于结构体条件与「零值忽略」语义。
- **二次利用**：泄露的 token/password 可用于登录、重置密码、伪造会话；也可配合其它接口的 IDOR。
- **关联**：同类 ORM 语义问题还包括软删除字段未生效、`Updates(struct)` 忽略零值导致字段无法更新等；审计时应对照 `Omit`/`Select` 与零值语义。

## 检测与防御

- **检测**：审计所有 `Where(&Struct{...})` 调用点，检查字段是否可能为零值、上层是否只校验参数存在性；抓包测试 `?param=`、`{"id":""}`、`0` 等边界值观察响应是否变为「第一条记录」。
- **防御**：显式校验参数非空（`if token == "" { return 400 }`）；使用 `Where(map[string]interface{})` 或 `Where("token = ?", token)` 显式拼接条件；`First` 前加唯一索引/非空约束；对返回字段做最小化（不返回 token/password 等敏感列）。
