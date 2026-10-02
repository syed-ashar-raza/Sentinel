FROM python:3.14-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY examples ./examples
RUN pip install --no-cache-dir .
EXPOSE 8000
CMD ["uvicorn","sentinel.api:app","--host","0.0.0.0","--port","8000"]
