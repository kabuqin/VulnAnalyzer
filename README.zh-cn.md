# 🔍 VulnAnalyzer v2.2

**多合一自动化漏洞检测与分析平台**

[![English](https://img.shields.io/badge/Language-English-blue)](README.md)
[![中文](https://img.shields.io/badge/Language-中文-red)](README.zh-cn.md)
![Version](https://img.shields.io/badge/version-2.2-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-Educational%20Use-red)

> 支持手动代码分析和自动网站扫描，内置 **24+** 漏洞类型检测引擎，自动生成 PoC，内置 **156+** PoC 参考库。

---

## 📋 目录

- [功能特性](#-功能特性)
- [快速开始](#-快速开始)
- [使用指南](#-使用指南)
- [检测能力](#-检测能力)
- [PoC 参考库](#-poc-参考库)
- [增强特性](#-增强特性)
- [API 文档](#-api-文档)
- [项目结构](#-项目结构)
- [常见问题](#-常见问题)
- [法律声明](#-法律声明)

---

## 🎯 功能特性

### 两种工作模式

| 模式 | 说明 |
|------|------|
| **Manual（手动分析）** | 粘贴代码 / HTTP 请求，实时检测漏洞 |
| **Scan（自动扫描）** | 输入 URL，自动爬取网站并检测全部漏洞 |

### 自动化流程

```mermaid
graph LR
    A[输入目标 URL] --> B[自动爬取];
    B --> C[提取表单/参数/链接];
    C --> D[智能漏洞检测];
    D --> E[结果分类 + PoC 生成];
    E --> F[一键导出报告];
```

### 核心能力

- **24+** 漏洞类型检测
- **SSE 流式推送** — 扫描进度实时显示
- **启发式匹配 + 代码模式识别**
- **自动 PoC 生成**
- **风险等级分类**（Info / Low / Medium / High / Critical）
- **CWE / OWASP 标准引用**
- **行号精确定位** — 精确到源代码行:列
- **代码行预览** — 直接展示匹配代码
- **JSON 导出报告**

---

## 🚀 快速开始

### 系统要求

- Python 3.8+
- pip 包管理器

### 安装与启动

```bash
# 1. 克隆仓库
git clone https://github.com/kabuqin/VulnAnalyzer.git
cd VulnAnalyzer

# 2. 安装依赖
pip install flask requests

# 3. 启动服务
python app.py

# 4. 打开浏览器访问
# http://127.0.0.1:5000
```

---

## 📖 使用指南

### 模式 1：Manual（手动分析）

1. 点击 **Manual** 标签
2. 在输入框中粘贴代码或 HTTP 请求
3. 点击 **Analyze**
4. 查看检测结果

**支持输入类型：**
- HTTP 请求（GET / POST / PUT / DELETE 等）
- HTML 源代码
- Java / Python / PHP / JavaScript 代码片段

**示例输入：**

```http
POST /admin/upload?id=1&redirect=http://evil.com HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=password
```

### 模式 2：Scan（自动扫描）

1. 点击 **Scan** 标签
2. 输入目标 URL（如 `https://example.com`）
3. 点击 **Scan Target**
4. 等待扫描完成，实时查看进度
5. 扫描完成后查看结果

### 模式 3：PoC 参考库

项目内置了覆盖 **PortSwigger Web Security Academy** 全部类别的 PoC 参考库：

1. 点击导航栏的 **PoC** 按钮
2. 左侧面板显示 **All（全部）** 和 **24 个分类按钮**
3. 点击 **All** 查看所有 156+ 个 payload
4. 点击具体分类（如 SQL Injection）只显示该类 payload
5. 支持 **搜索过滤**，输入关键词即时筛选
6. 点击 **Copy** 一键复制 payload

---

## 🔍 检测能力

### 漏洞类型（24+ 种）

| 漏洞类型 | 风险级别 | 检测方式 |
|---------|:-------:|---------|
| XSS（含污染链追踪） | **HIGH** | DOM source→sink、参数反射、模板表达式 |
| SQL 注入 | HIGH | 字符串拼接、错误信息、参数特征 |
| SSTI（模板注入） | **HIGH** | Jinja2 / Twig / Freemarker / Velocity / Thymeleaf 等 |
| 命令注入 | HIGH | Runtime.exec / ProcessBuilder / child_process |
| 路径遍历 | HIGH | `../` 序列检测 |
| SSRF（含链式 SSRF） | **HIGH** | URL 构造、私网检测、dataUrl 链 |
| 开放重定向 | Medium | redirect 参数分析 |
| 文件上传 | HIGH | 表单检测、验证标志 |
| XXE | **Critical** | DOCTYPE 检测 |
| 反序列化 | **Critical** | ObjectInputStream / Jackson / SnakeYAML |
| CORS 错误配置 | Medium | 通配符检测 |
| 敏感信息泄露 | HIGH | API Key、密钥、凭证识别 |
| 授权绕过 | HIGH | 参数直控、敏感路由 |
| 加密弱点 | HIGH | ECB、MD5、SHA1、弱 TLS |
| Log 注入 | Medium | 日志拼接检测 |
| SpEL 注入 | **Critical** | 表达式解析 |
| 不安全反射 | **Critical** | Class.forName / ClassLoader |
| 安全头缺失 | Low | 响应头检查 |
| 错误处理缺失 | **Medium** | async 无 try/catch、fetch 无 .catch() |
| CSRF | HIGH | 令牌验证 |
| JWT 攻击 | HIGH | 签名验证 |
| HTTP 请求走私 | **Critical** | Content-Length / Transfer-Encoding 解析 |
| NoSQL 注入 | HIGH | 参数特征 |
| WebSocket | Medium | Origin 验证 |
| GraphQL | Medium | 批量查询 / 自省 |

### 每个漏洞包含

- **位置信息** — 精确指出 **第 X 行 第 Y 列**
- **代码预览** — 直接展示匹配到的源代码行
- **证据** — 为什么认为存在此漏洞
- **验证步骤** — 如何进一步验证
- **PoC** — 自动生成的测试代码
- **CWE / OWASP** — 标准分类引用

---

## 📚 PoC 参考库

项目内置完整的 PoC 参考库，覆盖 **PortSwigger Web Security Academy 全部 24 类实验室**，包含 **156+ 条 payload**：

| 分类 | 数量 | 风险 |
|------|:---:|:----:|
| SQL Injection | 11 | Critical |
| XSS | 24 | High |
| SSTI | 10 | Critical |
| Path Traversal | 8 | High |
| Command Injection | 8 | Critical |
| XXE | 6 | High |
| SSRF | 8 | High |
| Open Redirect | 5 | Medium |
| CSRF | 5 | High |
| CORS | 4 | Medium |
| HTTP Request Smuggling | 5 | Critical |
| NoSQL Injection | 5 | High |
| JWT Attacks | 5 | High |
| Access Control / IDOR | 6 | High |
| File Upload | 6 | High |
| Insecure Deserialization | 6 | Critical |
| Web Cache Poisoning | 4 | Medium |
| Host Header Injection | 5 | Medium |
| GraphQL | 4 | Medium |
| Prototype Pollution | 4 | Medium |
| Clickjacking | 3 | Medium |
| WebSocket | 3 | Medium |
| Race Condition | 2 | High |
| LLM Attacks | 11 | Medium |

**XSS 无害化测试包** — 10 条不触发弹窗的安全测试 payload（使用 `console.log` 替代 `alert`），支持安全场景验证。

**一键复制** — 所有 payload 支持一键复制到剪贴板。

---

## ✨ 增强特性

### XSS 污染链追踪 🔗

检测完整的 source→sink 数据流：

```
URLSearchParams → params.get('userId') → fetch('/api/profile/') → ... → innerHTML
```

当检测到 DOM 数据源（URL 参数、location 等）流向 DOM 写入点（innerHTML、eval 等）时，标记为 **HIGH** 级别。

### 链式 SSRF 检测 🌐

检测一个 fetch 响应的字段被直接用于下一个 fetch 的安全风险：

```javascript
const meta = await fetch('/api/doc/1').then(r => r.json());
const data = await fetch(meta.dataUrl).then(r => r.json());  // ← 链式 SSRF
```

### SSTI（服务端模板注入）🧩

| 模板引擎 | 检测模式 |
|---------|---------|
| Jinja2 / Twig | `{{...}}`, `{%...%}` + 用户变量 |
| Freemarker / Velocity | `${...}` 表达式 |
| Thymeleaf | `th:text`, `th:utext` 属性 |
| Flask | `render_template_string()` + 请求数据 |
| Nunjucks / EJS | `compile()`, `render()` API |
| Smarty / Blade | PHP 模板渲染函数 |

### SSE 流式扫描进度 📊

Scan 模式使用 **Server-Sent Events（SSE）** 实时推送扫描进度，无需轮询：

```
[15:30:01] Target: https://example.com
[15:30:02] Crawling: page 1/10
[15:30:05] Found 3 forms, 12 params
[15:30:06] Analyzing page 2/10...
[15:30:30] Scan complete! Found 8 issues.
```

### 缺失错误处理 ⚠️

- 检测 async 函数缺少 `try/catch`
- 检测 fetch 调用缺少 `.catch()` 错误处理

### 行号定位 📍

所有发现不再使用晦涩的字符偏移量，而是展示 **第 X 行 第 Y 列**，并在详情中直接显示匹配到的源代码行。

---

## 🔌 API 文档

### POST /analyze

手动代码分析

```bash
curl -X POST http://127.0.0.1:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "text": "GET /admin?id=1 HTTP/1.1",
    "min_risk": "info",
    "types": ["XSS", "SQL Injection"]
  }'
```

**参数：**
- `text` (string) — 要分析的代码 / 请求
- `min_risk` (string) — 最低风险：info / low / medium / high / critical
- `types` (array) — 只检测指定类型，不填则全检

### POST /crawl

网站爬取与参数提取

```bash
curl -X POST http://127.0.0.1:5000/crawl \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "max_pages": 30
  }'
```

### POST /scan-target

完整自动扫描（非流式）

```bash
curl -X POST http://127.0.0.1:5000/scan-target \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "min_risk": "info"
  }'
```

### POST /scan-stream

SSE 实时流式扫描（带进度推送）

```bash
curl -X POST http://127.0.0.1:5000/scan-stream \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'
```

---

## ⚙️ 项目结构

```
VulnAnalyzer/
├── app.py                    # Flask 服务器（路由 + SSE 流式推送）
├── vuln_analyzer.py         # 检测引擎（2400+ 行，24+ 漏洞类型）
├── crawler.py               # 网站爬虫（表单/参数/链接提取）
├── static/
│   ├── index.html           # 前端 UI（深色主题，含 PoC 参考库面板）
│   └── poc_data.js          # PoC 参考库数据（24 类 156+ payload）
├── README.md                # 英文文档
├── README.zh-cn.md          # 中文文档
└── .gitignore
```

---

## ❓ 常见问题

### Q：为什么有大量检测结果？

A：VulnAnalyzer 使用启发式检测，会有误报。建议按风险等级过滤，并使用 PoC 进行手动验证。

### Q：支持 HTTPS 吗？

A：支持，默认跳过 SSL 验证。可修改 `crawler.py` 中的 `verify_ssl=True`。

### Q：支持 JavaScript 渲染吗？

A：不支持。爬虫仅解析静态 HTML。

### Q：如何扩展新的漏洞类型？

A：编辑 `vuln_analyzer.py`，添加新的 `analyze_xxx()` 函数，并在主 `analyze()` 函数中注册。

### Q：PoC 库中的 payload 是否安全？

A：PoC 库已通过纯 DOM API 渲染，所有 payload 使用 `textContent` 和 `dataset` 设置，不会在页面上执行任何脚本。XSS 无害化测试包使用 `console.log` 代替 `alert`，适合安全测试场景。

---

## ⚠️ 法律声明

**仅用于授权安全测试**

- ✅ 自己的项目
- ✅ 获得明确授权的目标
- ❌ 未授权网站扫描（违法）

---

## 📈 性能指标

| 任务 | 耗时 |
|------|:----:|
| 单个代码片段分析 | 1–10 ms |
| 爬取单个页面 | 1–3 s |
| 30 页网站完整扫描 | 2–5 min |
| 内存占用 | 50–100 MB |

---

**VulnAnalyzer v2.2** | Educational Use Only | [English](README.md) | [中文](README.zh-cn.md)
