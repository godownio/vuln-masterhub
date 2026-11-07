---
id: ai-security-ai-image-provenance-c2pa-tc260-strip-tamper
title: AI 生成图片溯源标识剥离与篡改：C2PA 重编码丢段、TC260 无签名可改
type: scenario
domain: ai-security
path: ai-security
technique: ai-image-provenance-c2pa-tc260-strip-tamper
tags:
- ai
- c2pa
- tc260
- provenance
- watermark
- anti-forensics
- metadata
- image
- evasion
- forensics
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V106
  verified_at: '2026-11-05T22:33:05+08:00'
  notes: 已对照全文与12张图核对：ChatGPT/Firefly 基线 FULL（ES256/PS256）、即梦 XMP-TC260/Aigc 无 C2PA（图07）、Pillow Q95/Q90/Q60/Q30 与截图/裁剪全部 NONE、PC 微信 10.8MB 透传 FULL（图08）、单字符改 C2PA 作者即 PARTIAL/Invalid（图11）、TC260 等长改 Label/ContentProducer 零告警、AI 再生成凭证换代，均与卡片一致。卡片已注明再签名与 exiftool -C2PA:all= 为原文提及/机制推导未单独实测；PoC 为原文脚本/命令，未本机复跑；无组件版本，未设 versions；frontmatter 无 sources/source_url。
url: /docs/ai-security/ai-security-ai-image-provenance-c2pa-tc260-strip-tamper/
draft: false
kb_aliases:
- C2PA 剥离
- 内容凭证删除
- TC260 隐式标识篡改
- AI 生成图片洗白
- exiftool -C2PA:all=
- Pillow 重编码丢 C2PA
- SynthID 对比
- 溯源标识存活率
---

## 一句话结论

AI 生成图片的 C2PA 内容凭证只是嵌在 JPEG APP11 / PNG caBX 中的签名元数据，任何重编码、截图、裁剪都会把它整体丢弃，删除成本几乎为零；国内《标识办法》配套的 TC260 隐式标识则是无签名的 XMP JSON，攻击者可等长修改 `Label`、`ContentProducer` 等字段把“AI 生成”改成“非 AI”，校验端不会产生任何告警——因此“检测不到凭证”不能证明“不是 AI 生成”，元数据溯源只能防无心丢失，防不住主动剥离与篡改。

## 原理

- **C2PA 的载体与绑定**：C2PA 内容凭证是一份 `manifest` 签名数据，内含生成信息、编辑历史、缩略图等断言；关键在 `hard binding`——manifest 写入最终图像的内容哈希，验证时重新计算哈希比对，因此凭证与像素内容锁死。签名使用 X.509 证书链，验证方应校验证书链与 C2PA 信任列表。JPEG 存在 APP11 应用段（JUMBF 容器），PNG 存在 `caBX` 自定义 chunk，且规范要求位于 `IDAT` 之前。
- **C2PA 的结构性弱点**：APP11、caBX 在“不认识 C2PA”的软件看来只是可丢弃的附加字节。图像处理软件通常只处理像素并重新编码，元数据段要么被丢弃、要么因像素变化导致哈希失配。实测：Pillow 以 Q95/Q90/Q60/Q30 重存 JPEG，四档全部 `NONE`，与压缩强度无关——杀死凭证的是“重编码”这个行为本身，而不是压缩率；系统截图、10% 裁剪 + 50% 缩放同样 `NONE`。
- **TC260 隐式标识的结构性弱点**：国内生成器（原文实测即梦）在 XMP 中写入 `XMP-TC260` 命名空间的 `Aigc` 字段，内容是一段 JSON，包含 `Label`（1 表示 AI 生成）、`ContentProducer`（服务提供者编码）、`ProduceID`、`ContentPropagator`、`PropagateID`。它只有声明、没有签名，字段可被任意修改且不存在哈希/证书校验；原文把 `Label:"1"` 改成 `"0"`、`ContentProducer` 改成 27 个 0（共 28 个字符的等长替换），检测结果仍是 `META-OTHER`，零告警。
- **两类标准的对照**：C2PA 对篡改是敏感的——原文把 manifest 内作者字段 `Joe Bloggs` 改一个字符为 `Joe Blogg0`，验证状态立刻变为 `Invalid`（哈希失配），说明密码学防线有效；TC260 对篡改是沉默的——因为它没有签名。两者的共同弱点是“凭证必须还活着且有人去验”：剥离后的文件与从未带过凭证的文件在字节层面无法区分，而绝大多数看图场景（聊天窗、浏览器、相册）没有 C2PA 验证 UI。
- **传播链存活规律**：字节不变的环节全部存活（无损复制 100%，2026 版 PC 微信文件传输助手对 PNG/269KB JPEG/10.8MB JPEG 均字节级透传 100%）；涉及重编码或渲染的环节全部归零（截图 0%、Pillow 重压缩 0%、裁剪缩放 0%）。AI 再生成是特殊情形：旧凭证随旧图死亡，生成器给新图签发一张全新的、密码学完全合法的凭证（仍标 AI），溯源链在“原图→再生成”处断开，但检测状态是 `FULL`——即“有凭证”不等于“溯源成立”。
- **攻击者视角的三条路径**：
  1. **剥离（strip）**：Pillow 重存一遍或 `exiftool -C2PA:all=` 定向删除，凭证变为 `NONE`；截图是零工具、零成本的等价操作，且同时清掉 EXIF 与其他字节证据。剥离后的图无法被证明“曾经有过凭证”。
  2. **篡改（tamper）**：对 TC260 这类无签名标识，直接等长改字段即可把 AI 图伪装成非 AI 图；对 C2PA，直接改 manifest 会触发哈希失配（`PARTIAL/Invalid`），不适合作为隐蔽篡改手段。
  3. **再签名（re-sign）**：剥离原凭证后用自签证书签一份“摄影师作品”的假 manifest。签名在密码学上能通过，但验证端检查信任列表时会显示“未受信任的签名”；现实问题是大多数平台和用户根本不跑验证流程，因此这条路径的威胁取决于验证方的执行力（原文称技术可行但未实测）。
- **AI 再生成的“凭证换代”**：把带凭证的 AI 图喂回生成器模仿再画，输出图带一张新的、合法的 C2PA 凭证。旧凭证的溯源链断裂，新凭证只证明“新图由某模型生成”，并不声明参考了原图；如果检测方只看“有没有凭证”，会把新图当成合法的 AI 图，但若目标是伪装成非 AI 图，再生成本身不解决问题（仍标 AI），通常还要叠加剥离。

## 触发条件

- 攻击者已拿到目标图片文件（生成后、传播中均可），不需要访问生成器账号或后端。
- 图片带 C2PA（如 ChatGPT/gpt-image、Adobe Firefly）或国内 TC260 隐式标识（如即梦等生成器）；无标识的图无需处理。
- 剥离依赖任意会重编码图片的工具（Pillow、常见修图软件）或截图；`exiftool -C2PA:all=` 可直接定向删除 C2PA 段（原文提及该命令，未单独实测）。
- 篡改 TC260 需要能编辑 XMP 元数据；字段值是 HTML 实体转义形态（如 `&quot;Label&quot;`），需先反转义再解析 JSON；等长替换可保持文件大小不变，降低被发现概率。
- 验证方未执行 C2PA 校验，或只看“有无凭证/标识”而不校验证书链与哈希；平台展示环节没有溯源 UI。
- 对像素级水印（如 Google SynthID）无效：水印调制在像素中，剥离元数据不会移除水印，需要改动像素并承担画质损失。

## 利用步骤

1. **识别凭证类型**：用 c2pa-python SDK/`c2patool` 读取 C2PA manifest；读不到时用 `exiftool -j` 检查 XMP 中是否存在 `XMP-TC260/Aigc` 等 AI 生成字段，区分“无 C2PA 但有国标标识”“完全无标识”两种情况。
2. **选择剥离路径**：对 C2PA 图片，用 Pillow 打开后重新保存为 JPEG（任意质量）即可丢弃 APP11/caBX；或用 `exiftool -C2PA:all=` 定向删除；最省事的是系统截图（同时清除 EXIF 与字节级痕迹）。对 TC260 图片，重编码/截图同样会清除 XMP 标识。
3. **验证剥离结果**：再次用 c2pa SDK 读取应为 `NONE`，`exiftool` 不再出现 AI/C2PA/生成属性字段；文件与从未带凭证的图片在字节层不可区分。
4. **篡改无签名标识**：对 TC260 的 XMP JSON 做等长替换——`Label` 从 `1` 改为 `0`，`ContentProducer`/`ContentPropagator` 改成无效编码，`ProduceID`/`PropagateID` 可保留或替换；保持 JSON 长度和 HTML 实体转义格式，写回 XMP。
5. **复检与规避**：用 C2PA 库确认仍为 `NONE`，用 exiftool 确认字段值已变且没有校验错误；如目标平台只检查“是否带 AI 标识”，此时已可把 AI 图当作非 AI 图提交。
6. **可选的再签名**：剥离后用自签证书给图片签一份声称“摄影作品”的 manifest；验证端若校验证书链会显示不受信任，若平台不验证则外观上与合法凭证无异（原文未实测）。
7. **传播与洗白**：若只需要绕过“有凭证即 AI”的检测，剥离即可；若要绕过“无凭证也可疑”的检测，需要配合像素级处理或再生成，但会引入画质/内容变化。

## PoC

Pillow 重编码剥离 C2PA（实测 Q95/Q90/Q60/Q30 均导致 `NONE`）：

```python
from PIL import Image

img = Image.open("chatgpt_ai.png").convert("RGB")
img.save("laundered.jpg", quality=90)   # APP11/caBX 被丢弃，C2PA manifest 消失
```

ExifTool 定向删除 C2PA 段：

```bash
exiftool -C2PA:all= -overwrite_original laundered.jpg
```

TC260 隐式标识等长篡改（示意；字段值来自实测结构）：

```python
import html, json

# XMP-TC260/Aigc 的原始值在 XML 中是 HTML 实体转义形态
raw = '{"Label":"1","ContentProducer":"00119144030008867405X210001",' \
      '"ProduceID":"tos-cn-i-tb4s082cfz/1d142b46...",' \
      '"ContentPropagator":"00119144030008867405X220001",' \
      '"PropagateID":"tos-cn-i-tb4s082cfz/1d142b46..."}'
d = json.loads(html.unescape(raw))
d["Label"] = "0"                       # AI 生成 -> 非 AI
d["ContentProducer"] = "0" * 27        # 等长替换，文件大小不变
out = html.escape(json.dumps(d, separators=(",", ":")), quote=True)
# 将 out 写回 XMP-TC260/Aigc；exiftool 复检仍为 META-OTHER，无任何校验错误
```

C2PA 篡改对照（会被检测出来，不适合隐蔽篡改）：

```python
# 将 manifest 内作者字段 Joe Bloggs 等长改为 Joe Blogg0
# 结果：validation state = Invalid / PARTIAL，哈希失配暴露
```

检测侧四级判定（原文自研脚本核心逻辑，c2pa-python + exiftool 兜底）：

```python
import json, subprocess
import c2pa

def inspect(path):
    try:
        r = c2pa.Reader.try_create(path.replace("\\", "/"))
        j = json.loads(r.json())
        m = j.get("active_manifest")
        if not m:
            return exif_fallback(path)
        state = str(r.get_validation_state())
        return ("FULL" if state.lower() == "valid" else "PARTIAL", state)
    except c2pa.C2paError:
        return exif_fallback(path)

def exif_fallback(path):
    e = subprocess.run(["exiftool", "-charset", "filename=UTF8", "-j", path],
                       capture_output=True, text=True)
    data = json.loads(e.stdout) if e.stdout.strip() else []
    ai_fields = {k: v for d in data for k, v in d.items()
                 if any(t in k.lower() for t in ("ai", "generat", "synth", "c2pa"))}
    return ("META-OTHER", str(ai_fields)) if ai_fields else ("NONE", "")
```

## 变体与关联

- **截图/裁剪/缩放**：零工具或轻量编辑即可让 C2PA 与 TC260 同时归零；截图的特殊性在于不需要任何编辑软件，是成本最低的“洗白”路径，也是元数据溯源的根本盲区。
- **AI 再生成**：旧凭证死亡、新图获得全新合法凭证，检测状态仍 `FULL`；若检测方只看“有无凭证”，无法区分“原图”和“换代图”，必须核对 manifest 生成时间、内容描述与图像本身的对应关系。
- **再签名伪造**：剥离后自签一份“非 AI/摄影作品”manifest；证书链不受信任是唯一破绽，依赖验证方执行完整校验并在 UI 明示。原文未实测，属于机制推导。
- **像素级水印的对抗**：SynthID 等水印调制在像素中，剥离元数据无效；攻击者必须修改像素（压缩、重绘、加噪）并承担画质损失，这构成“元数据 + 水印”分层防御的基础。
- **不同生成器/格式**：C2PA 在 JPEG/PNG/WebP/TIFF/MP4 各有容器；TC260 字段名和编码可能因厂商而异（原文实测即梦使用 `XMP-TC260/Aigc`），检测脚本需按数据补充关键词而非预设固定字段。
- **关联卡片**：[[defense-detection-proram-agent-signed-hello-mutex-run-key]]（同为签名/信任链校验视角的检测卡，可对照“验证方不校验则凭证无效”的思路）；[[defense-forensics-email-header-spoof-detection]]（伪造与硬信号判定的取证思路）。

## 检测与防御

- **别把“无凭证”当“非 AI”**：`NONE` 只表示文件里没有 C2PA manifest，可能是从未生成、被剥离或格式不支持；必须结合 `META-OTHER`（TC260 等国产标识）、像素级水印检测与生成器侧日志综合判断。
- **四级状态判定**：用 c2pa-python/c2patool 读取并验证签名与哈希，区分 `FULL`（完整有效）、`PARTIAL`（manifest 存在但哈希/签名异常，提示被改过）、`NONE`（无 C2PA）、`META-OTHER`（无 C2PA 但有其他 AI 生成元数据）；exiftool 作为兜底，注意中文路径加 `-charset filename=UTF8`。
- **平台侧主动校验**：在图片上传/展示链路自动运行 C2PA 验证，向用户明示“已签名/未受信任/无凭证”，把“自愿校验”变成默认校验；仅保存凭证而不校验等于没有护照。
- **分层溯源**：元数据凭证（信息全、无损传播可校验）+ 像素级水印（跟随像素、抗截图/压缩）+ 平台校验与 UI 明示 + 生成器合规义务；任何单层都可被绕过，叠加才能抬高攻击成本。
- **合规与标准改进**：国内 TC260 隐式标识应引入签名/哈希绑定，避免“只有声明没有防篡改”；对生成器与服务提供者做标识写入审计；对剥离/篡改行为在平台侧做异常检测（上传图片元数据缺失但视觉特征疑似 AI）。
- **传播链保真**：社交平台/网盘在转码时保留或重新签发凭证；对需要保留出处的图片使用无损传输；企业图库对 AI 图片做入库校验与元数据备份。
- **取证注意**：收到疑似 AI 图片时，先保留原始文件（不要截图/转发/另存），再跑 C2PA/TC260 检测；若凭证已丢失，记录文件来源、传播路径与像素级检测结果，不能仅凭“无标识”下结论。
