FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml requirements-test.txt requirements-test-lock.txt ./
COPY inodeledger ./inodeledger
COPY tests ./tests
RUN python -m pip install --no-cache-dir -e . -r requirements-test-lock.txt
# Tk is deliberately absent; the desktop test skips in headless containers.
CMD ["python", "-m", "pytest", "-q"]
