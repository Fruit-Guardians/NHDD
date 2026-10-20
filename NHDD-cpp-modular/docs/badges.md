# NHDD 产品标识与 README 徽章

返回[工具使用说明](../README.md)。

README 首屏以产品标识、项目名和一句话定位为主体。徽章仅说明运行环境与技术属性，不承担功能目录，也不代表测试结果。

## 产品标识

![NHDD 标识](../assets/nhdd-mark.svg)

`assets/nhdd-mark.svg` 是 NHDD 的几何 N 标识。浅色圆角底板让标识在 GitHub 的深、浅色主题下均保持稳定；独立的小方块表示从内存中提取的字节。标识与文字均使用 SVG，可无损缩放，不依赖图床。

README 中按 104 × 104 显示，保留标识周围留白。标题只使用项目名 NHDD，完整名称 No-Hook DEX / SO Dumper 放在副标题中。

## 信息徽章

| 预览 | 说明 |
|---|---|
| ![Android Root](../assets/badges/nhdd-root.svg) | 当前主要运行场景是 Root Android |
| ![ARM64 / ARMv7](../assets/badges/nhdd-abi.svg) | ARM64 为主要真机验证环境；ARMv7 已通过交叉编译检查，不表示所有机型均已测试 |
| ![No Hook](../assets/badges/nhdd-no-hook.svg) | 默认在目标进程外读取内存，不依赖进程内注入或 ART Hook |
| ![C++17](../assets/badges/nhdd-cpp.svg) | 工具使用 C++17 构建 |

徽章统一高 20 px，使用常规双段结构、轻圆角与低饱和配色。Root 使用项目的绿色强调色，其余以灰蓝为主；不增加切角、发光、纹理或大面积彩色装饰。

功能介绍、参数和产物含义由正文负责，首屏只保留少量真实属性。所有资源保存在仓库中，外部服务不可用或离线阅读时也可显示。

## 在 README 中使用

```html
<p align="center">
  <img src="assets/nhdd-mark.svg" alt="NHDD" width="104" height="104">
</p>

<h1 align="center">NHDD</h1>

<p align="center">
  <img alt="Android · Root" src="assets/badges/nhdd-root.svg">
  <img alt="ABI · ARM64 / ARMv7" src="assets/badges/nhdd-abi.svg">
  <img alt="Capture · No Hook" src="assets/badges/nhdd-no-hook.svg">
  <img alt="C++ · 17" src="assets/badges/nhdd-cpp.svg">
</p>
```

从仓库根 README 引用时，将资源前缀改为 `NHDD-cpp-modular/assets/`。导航使用普通文本链接，不把每个入口再做成一个视觉组件。

## 维护规则

- SVG 的 `title / desc` 与 README 的 `alt` 应准确描述当前能力。
- 添加徽章前先判断它是否确实帮助读者了解工具；版本检查、捕获策略等细节优先写进正文。
- 不使用静态徽章宣称 CI passing、全壳兼容、完整方法恢复或不可检测。
- 如果以后展示 Stars、Release 或 CI，使用真实的数据源，不手写统计数字。通用动态徽章可参考 [Shields.io 文档](https://shields.io/badges/static-badge)。
