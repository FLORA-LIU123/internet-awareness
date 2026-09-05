# 🛡️ 网络安全态势感知与风险预警平台

基于 Streamlit + NeuralProphet 的零权限网络安全监测平台，支持 TLS 安全评估、威胁情报集成、时序预测与异常告警。

## 🌐 在线访问

### 一键部署到公网（免费）

**方式一：双击运行部署脚本**
```bash
# Windows 用户
双击 deploy.bat

# Mac/Linux 用户
bash deploy.sh
```

**方式二：手动部署到 Streamlit Cloud**

1. **创建 GitHub 仓库**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/YOUR_USERNAME/internet-awareness.git
   git push -u origin main
   ```

2. **部署到 Streamlit Cloud**
   - 访问：https://share.streamlit.io/
   - 登录后点击 "New app"
   - 配置：
     - Repository: `YOUR_USERNAME/internet-awareness`
     - Branch: `main`
     - Main file: `app/main.py`
   - 点击 "Deploy"

3. **获得公网链接**
   ```
   https://internet-awareness.streamlit.app
   ```
   全球任何人都能通过这个链接访问你的平台！

### 设置访问密码（可选）

在 Streamlit Cloud 的 App settings → Secrets 中添加：
```toml
APP_PASSWORD = "your_secure_password"
OTX_API_KEY = "your_otx_api_key"
```

## 🚀 本地运行

```bash
# 安装依赖
pip install -r requirements.txt

# 启动平台
streamlit run app/main.py
```

访问：http://localhost:8501

## ✨ 核心功能

- 🛡️ **TLS/HTTPS 安全评估**：协议版本、加密套件、证书有效期
- 🔍 **威胁情报集成**：AlienVault OTX 恶意 IP/域名检测
- 📊 **时序预测**：NeuralProphet 深度学习预测（79天数据点已达最优模型）
- 🚨 **实时告警**：安全劣化、异常流量、证书过期预警
- 📈 **健康度评分**：多维度综合评分与趋势分析
- 📋 **等保合规**：自动生成安全评估报告

## 📊 预测模型阶段

- **2-4个数据点**：线性趋势外推
- **5+个数据点**：NeuralProphet 深度预测（自动降级到 Holt-Winters）

当前已积累 **79个日数据点**，已达最优预测精度。

## 🔧 技术栈

- **前端**：Streamlit
- **时序预测**：NeuralProphet, Holt-Winters, PyTorch
- **数据存储**：SQLite
- **图表可视化**：Plotly
- **威胁情报**：AlienVault OTX API
- **任务调度**：APScheduler

## 📁 项目结构

```
internet_awareness/
├── app/
│   ├── main.py              # 主入口
│   ├── pages/               # 各功能页面
│   └── styles.py            # 样式配置
├── src/
│   ├── collection/          # 数据采集
│   ├── prediction/          # 时序预测
│   ├── scoring/             # 健康度评分
│   └── storage/             # 数据存储
├── scheduler/               # 定时任务
├── config/                  # 配置文件
├── requirements.txt         # 依赖列表
├── deploy.bat               # Windows 部署脚本
└── deploy.sh                # Linux/Mac 部署脚本
```

## 🎯 监测能力

- ✅ HTTP/HTTPS 可用性监测
- ✅ 响应时延分析
- ✅ DNS 解析性能
- ✅ SSL/TLS 证书监控
- ✅ 威胁情报匹配
- ✅ 链路质量评估
- ✅ 安全合规检查

## 📝 部署注意事项

1. **环境变量配置**：
   - `APP_PASSWORD`：设置访问密码保护你的平台
   - `OTX_API_KEY`：从 https://otx.alienvault.com/ 获取免费API密钥

2. **资源限制**：
   - Streamlit Community Cloud：免费，1GB RAM，适合个人使用
   - Railway/Heroku：免费额度有限，需要升级付费套餐
   - 自建服务器：完全控制，但需要维护成本

3. **数据持久化**：
   - Streamlit Cloud 重启后数据会丢失
   - 建议配置外部数据库（PostgreSQL/MySQL）或对象存储

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License

---

**开始使用**：双击 `deploy.bat`（Windows）或运行 `bash deploy.sh`（Mac/Linux）一键部署到公网！