# Multi-stage build for optimized production image
FROM python:3.11-slim as builder

# Set build arguments
ARG POETRY_VERSION=1.7.1

# Install system dependencies needed for building
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install poetry==$POETRY_VERSION

# Set Poetry configuration
ENV POETRY_NO_INTERACTION=1 \
    POETRY_VENV_IN_PROJECT=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

# Set working directory
WORKDIR /app

# Copy Poetry files
COPY pyproject.toml poetry.lock ./

# Install dependencies
RUN poetry install --only=main && rm -rf $POETRY_CACHE_DIR

# Production stage
FROM python:3.11-slim as production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd -r wtfcodebot && useradd -r -g wtfcodebot wtfcodebot

# Set working directory
WORKDIR /app

# Copy virtual environment from builder stage
COPY --from=builder /app/.venv /app/.venv

# Copy application code
COPY wtf_codebot/ ./wtf_codebot/
COPY templates/ ./templates/
COPY custom_templates/ ./custom_templates/
COPY pyproject.toml ./

# Create directories for reports and cache
RUN mkdir -p /app/reports /app/cache && \
    chown -R wtfcodebot:wtfcodebot /app

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app" \
    WTF_CODEBOT_CACHE_DIR="/app/cache" \
    WTF_CODEBOT_REPORTS_DIR="/app/reports"

# Switch to non-root user
USER wtfcodebot

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from wtf_codebot.cli.main import main; print('OK')" || exit 1

# Default command
ENTRYPOINT ["python", "-m", "wtf_codebot.cli.main"]
CMD ["--help"]

# Labels for metadata
LABEL org.opencontainers.image.title="WTF CodeBot" \
      org.opencontainers.image.description="AI-powered code analysis and review tool" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.vendor="WTF CodeBot Team" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/your-org/wtf-codebot" \
      org.opencontainers.image.documentation="https://github.com/your-org/wtf-codebot/blob/main/README.md"

# Development stage (optional, for development use)
FROM production as development

# Switch back to root for development tools installation
USER root

# Install development dependencies
RUN apt-get update && apt-get install -y \
    vim \
    nano \
    less \
    htop \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install development Python packages
COPY --from=builder /app/ /app/
RUN /app/.venv/bin/pip install poetry && \
    cd /app && /app/.venv/bin/poetry install --with dev

# Switch back to non-root user
USER wtfcodebot

# Default command for development
CMD ["bash"]
