# VulnAnalyzer 2.1 - Quick Start

## 文件列表
- `app.py` - Flask Web 服务器
- `vuln_analyzer.py` - 漏洞检测引擎
- `crawler.py` - 网站爬虫
- `static/index.html` - 前端页面（或直接放在根目录）

## 目录结构
```
project/
├── app.py
├── vuln_analyzer.py
├── crawler.py
└── static/
    └── index.html
```

## 安装 & 启动

### 1. 安装依赖
```bash
pip install flask requests
```

### 2. 启动服务
```bash
python app.py
```

### 3. 打开浏览器
```
http://127.0.0.1:5000
```

## 两种使用模式

### 模式 1: Manual (手动分析)
- 粘贴代码/HTTP请求
- 点击 Analyze 按钮
- 查看检测结果和 PoC

### 模式 2: Scan (自动扫描)
- 输入目标 URL
- 点击 Scan Target 按钮
- 自动爬取+检测+报告

## 检测漏洞类型
- XSS
- SQL Injection
- Path Traversal
- SSRF
- Cmd Injection
- Open Redirect
- File Upload
- XXE
- 反序列化
- 以及更多...

## 每个漏洞都包含
- 位置信息
- 证据
- 验证步骤
- PoC 测试代码
- CWE 参考

## 故障排除

**问题：找不到 static/index.html**
- 解决：确保目录结构正确，或把 index.html 放在项目根目录

**问题：爬虫超时**
- 调整 max_pages 参数（默认 30，可改为更小的值）

**问题：检测漏洞过多**
- 使用风险过滤（min_risk 参数）只显示高危漏洞
