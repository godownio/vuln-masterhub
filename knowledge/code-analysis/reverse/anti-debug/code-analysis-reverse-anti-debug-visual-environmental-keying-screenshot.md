---
id: code-analysis-reverse-anti-debug-visual-environmental-keying-screenshot
title: 截屏像素统计做视觉环境键控：以桌面壁纸特征识别沙箱而不触发高敏感行为
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: visual-environmental-keying-screenshot
aliases:
- 视觉环境键控
- Visual Environmental Keying
- 截图反沙盒
- 壁纸特征识别沙箱
- GDI 截屏反沙箱
tags:
- anti-debug
- anti-sandbox
- evasion
- windows
- gdi
- screen-capture
- environmental-keying
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V76
  verified_at: '2026-11-05T16:27:52+08:00'
  notes: 已对照原文与 img/01-03 核对：GDI 截屏 GetDC(NULL)/BitBlt/GetDIBits、顶部 20% 右半区蓝色≥80% 与中心白色 1%-20% 阈值、命中后 MessageBoxW 均与原文一致；img/02 为沙箱内命中后的微步云弹框，img/03 为微步云沙箱报告。原文未给受影响版本，未设置 affected_versions；PoC 未在本机执行；frontmatter 无 sources/source_url（worker brief 要求不写来源）。
---

## 一句话结论

不查询虚拟机文件、注册表、CPU 指令或时间加速，而用 Windows GDI 截取桌面的一小块区域，统计“背景蓝色占比”和“中心白色文字占比”来匹配已知沙箱壁纸；命中后才确认身处沙箱并按需改变行为，整个过程只有一次普通截图调用，行为特征远低于传统反沙箱探测。

## 原理

- 沙箱/自动化分析平台普遍使用标准化、纯净的 Windows 虚拟机，桌面壁纸固定且可公开获取（如厂商品牌壁纸、默认蓝色背景、无图标干净桌面）；真实用户桌面则杂乱且各不相同。壁纸因此成为一个稳定、可远程获知的环境指纹。
- 传统反沙箱依赖 `NtQueryInformationProcess`、时间加速、桌面文件数、用户名/主机名、VMware/VirtualBox 注册表键等，这些组合本身就会被沙箱和 EDR 标记为高敏感行为。视觉键控把判断依据移到“屏幕上看到的内容”，不产生这些 API 调用。
- GDI 的 `GetDC(NULL)` → `CreateCompatibleBitmap` → `BitBlt` → `GetDIBits` 是截图、远程桌面、录屏、无障碍工具都在用的通用链路；单独调用不足以判定恶意。
- 像素判断不需要 OpenCV/OCR：直接比较 BITMAPINFO 的 BGRA 分量即可。示例判据为
  - 目标蓝：`b >= r + 50`、`b >= g + 20`、`b >= 140`、`r <= 100`；
  - 白色：`r > 200 && g > 200 && b > 200`。
- 为了降低干扰与耗时，不扫全屏：只取顶部约 20% 的右半区判断背景蓝（避开任务栏与图标区），再取屏幕中心 30%–70% × 45%–55% 的区域判断白色文字占比。使用比例而非精确匹配，能容忍分辨率、缩放和字体差异。
- 判定阈值：顶部蓝色像素占比 ≥ 80%，且中心白色像素占比在 1%–20% 之间，即认为壁纸匹配。白色占比上限用于排除纯白窗口或高亮页面造成的误报。

## 触发条件

- 目标为 Windows，样本运行在可截图的交互式用户会话中；服务会话/锁屏安全桌面下 `GetDC(NULL)`/`BitBlt` 可能拿不到真实桌面。
- 沙箱壁纸稳定且可从公开报告、产品截图或默认镜像中提前获知。
- 样本可在主逻辑前执行截图与像素统计，且能接受一次截图调用的行为开销。
- 分辨率/缩放变化在阈值容忍范围内，或按多分辨率分别校准。
- 若用于“沙箱内退出、真实机执行”，需要把分支逻辑反过来：命中壁纸时走良性路径，未命中时才释放真实 payload。

## 利用步骤

1. 收集目标沙箱的桌面特征：从公开沙箱报告、产品宣传图或默认镜像获取壁纸截图，确定背景主色与中心文字/Logo 的位置。
2. 选定两个小区域：一个纯背景区（如顶部 20% 右半区），一个中心文字区（如水平 30%–70%、垂直 45%–55%）。
3. 用 GDI 截全屏到内存位图，`GetDIBits` 转为 32 位 BGRA 像素数组。
4. 分别统计目标蓝与白色的像素占比，按阈值判断；先判断背景蓝，再判断中心白，减少计算量。
5. 命中时走沙箱分支（演示中弹出一个标识消息框；实战中应静默退出或执行良性行为）；未命中时走真实目标分支。
6. 在沙箱与真实机器上分别验证误报/漏报，按目标常见分辨率与 DPI 缩放校准阈值；可对多个区域取“与”/“或”组合提高稳定性。
7. 保持实现轻量：只用系统 DLL，不引入 OpenCV/OCR，不启动子进程，不读虚拟机注册表。

## PoC

```cpp
#include <windows.h>
#include <vector>

struct Color { unsigned char b, g, r, a; };

static bool IsTargetBlue(const Color& c) {
    return c.b >= c.r + 50 && c.b >= c.g + 20 && c.b >= 140 && c.r <= 100;
}
static bool IsWhite(const Color& c) {
    return c.r > 200 && c.g > 200 && c.b > 200;
}

bool CaptureScreen(int& w, int& h, std::vector<Color>& px) {
    w = GetSystemMetrics(SM_CXSCREEN);
    h = GetSystemMetrics(SM_CYSCREEN);
    HDC screen = GetDC(NULL);
    HDC mem = CreateCompatibleDC(screen);
    HBITMAP bmp = CreateCompatibleBitmap(screen, w, h);
    SelectObject(mem, bmp);
    if (!BitBlt(mem, 0, 0, w, h, screen, 0, 0, SRCCOPY)) return false;

    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = -h;          // 负高度：自上而下
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;
    px.resize(w * h);
    bool ok = GetDIBits(mem, bmp, 0, h, px.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);

    DeleteObject(bmp); DeleteDC(mem); ReleaseDC(NULL, screen);
    return ok;
}

bool LooksLikeTargetWallpaper(const std::vector<Color>& px, int w, int h) {
    long blue = 0, total = 0;
    for (int y = 0; y < (int)(h * 0.2); ++y)
        for (int x = w / 2; x < w; ++x) {
            if (IsTargetBlue(px[y * w + x])) ++blue;
            ++total;
        }
    if (total == 0 || (double)blue / total < 0.8) return false;

    int y0 = (int)(h * 0.45), y1 = (int)(h * 0.55);
    int x0 = (int)(w * 0.30), x1 = (int)(w * 0.70);
    long white = 0, center = (long)(y1 - y0) * (x1 - x0);
    for (int y = y0; y < y1; ++y)
        for (int x = x0; x < x1; ++x)
            if (IsWhite(px[y * w + x])) ++white;

    double ratio = (double)white / center;
    return ratio > 0.01 && ratio < 0.20;
}
```

```text
命中后（演示）：MessageBoxW(NULL, L"微步云", L"检测结果", MB_ICONINFORMATION);
实战分支：命中 -> 静默退出/良性行为；未命中 -> 释放并执行真实 payload。
```

## 变体与关联

- 变体：用桌面图标数量、任务栏布局、屏幕分辨率与 DPI 组合成更细的环境指纹，但仍应优先选择低敏感调用。
- 变体：对已知壁纸做降采样模板匹配，或只检测品牌 Logo 的主色/形状；也可用 `PrintWindow`/`GetWindowDC` 截取特定窗口。
- 变体：Linux 下用 X11 `XGetImage`/`XShmGetImage`、Wayland 下受权限限制；macOS 需屏幕录制权限，行为特征更明显。
- 关联：[[code-analysis-reverse-anti-debug-sandbox-environment-checks]]（传统时间加速、桌面文件数、主机名与 DebugPort 检查，本卡是其低行为替代方案）；[[pentest-c2-indirect-syscall-ntdll-hook-bypass]]（另一类减少用户态可见行为的思路）。
- 边界：沙箱若每次随机化壁纸/使用真实用户桌面镜像，或样本在无交互桌面运行，视觉键控失效；真实用户使用相同壁纸时会产生误报；截图 API 在部分 EDR 中仍可被标识，需结合进程信誉与调用时机。

## 检测与防御

- 检测：监控样本早期对 `GetDC(NULL)`、`BitBlt`、`GetDIBits`、`CreateCompatibleBitmap` 的调用组合；对“截屏后读取像素、无窗口/无用户交互”的进程提高评分；观察样本是否在截图后按分支快速退出。
- 防御（沙箱侧）：用真实用户桌面镜像并随机化壁纸、图标、分辨率与 DPI；在无稳定视觉特征的虚拟桌面中运行；对样本多轮、延迟执行，避免首轮即被视觉键控识别。
- 防御（终端侧）：对未签名程序调用截屏 API 做行为审计；限制非交互服务的桌面访问；结合进程信誉、网络行为与后续动作综合判断，而不是只看单次截图。
- 加固：屏幕录制权限最小化；企业环境统一壁纸反而会成为可预测特征，敏感主机应避免使用公开可查的固定壁纸。
