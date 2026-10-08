FROM python:3.11-slim
RUN useradd -m -u 1000 user
WORKDIR /app
ENV PATH="/home/user/.local/bin:${PATH}" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
COPY --chown=user requirements.txt .
USER user
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=user . .
# Train the secondary classifier at build time (dataset is in the repo; no runtime downloads).
RUN python scripts/train_classifier.py
EXPOSE 7860
# Hugging Face sets SPACE_HOST at runtime; the extension package is built then so it points at this Space.
CMD ["sh", "-c", "python scripts/package_extension.py && uvicorn app.main:app --host 0.0.0.0 --port 7860"]
