# 正式域名迁移（2026-11-08）

正式门户：https://godownio-vuln-masterhub.hf.space/

MCP：https://godownio-vuln-masterhub.hf.space/mcp

Space：https://huggingface.co/spaces/godownio/vuln-masterhub

GitHub Pages 仍为 https://godownio.github.io/vuln-masterhub/ 。其登录及 API Key 控制台入口已同步切至新域名。

用户自行将 HF 用户名从 Downio 改为 godownio 后，原 Space 的 Secrets、长期 Trusted Publisher 授权随仓库保留。发布工作流已将 HF_OIDC_RESOURCE、上传目标、Hugo baseURL 和运行状态检查目标全部切换到新命名空间。HF 公开变量 PORTAL_BASE_URL 显式指向新域名；数据库和会话签名配置保持原值。

GitHub OAuth App 保留 http://localhost:3000/callback，线上回调改为 https://godownio-vuln-masterhub.hf.space/callback，Homepage URL 同步使用正式门户。新域名需要重新登录一次，域名之间不共享 Cookie。

验收结果：

- 后端发布及运行检查成功：[Actions 42393767483](https://github.com/godownio/vuln-masterhub/actions/runs/42393767483)。
- Pages 发布成功：[Actions 42393774490](https://github.com/godownio/vuln-masterhub/actions/runs/42393774490)。
- 真实账号 godownio 登录成功；原有 1 个收藏、历史撤销记录保留；首页仍为 400 个节点。
- 3,640 张卡片与 36,944 个分块覆盖完整。MCP initialize、列工具、两条限定目录的混合向量搜索、详情读取通过。
- 两条改写查询的预期卡片均排第 1，semantic_used=true；耗时 16.13s、10.05s。这只是功能样本，不代表统计准确率或稳态性能。
- 一小时验收 Key 已撤销。未带 Key 和使用已撤销 Key 均返回 401；本地临时明文 Key 文件已删除。未做暴力请求或压力测试。

后续客户端配置仅需使用新的 MCP URL，并携带个人有效 API Key。不要把数据库连接串、GitHub OAuth Secret 或签名密钥放入客户端。
