FROM python:3.9-slim

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 拷贝代码
COPY . .

# 暴露 8000 端口
EXPOSE 8000

# 订阅 Token 位于查询参数中，禁用访问日志以免凭据写入容器日志。
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
