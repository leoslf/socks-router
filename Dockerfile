ARG DOCKER_REGISTRY
FROM ${DOCKER_REGISTRY:+${DOCKER_REGISTRY}/}python:3.12-slim-bullseye AS base

WORKDIR /usr/src/app

ARG POETRY_VERSION=1.7.1
ENV POETRY_VERSION=${POETRY_VERSION}
ENV POETRY_HOME=/opt/poetry
ARG POETRY_CACHE_DIR=/opt/.cache
ENV POETRY_CACHE_DIR=${POETRY_CACHE_DIR}

FROM base AS poetry

# pip install
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m venv $POETRY_HOME && \
    $POETRY_HOME/bin/pip install -U pip setuptools poetry==${POETRY_VERSION?}

FROM base AS runtime

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update -y && \
    apt-get install --no-install-recommends -y openssh-client curl

COPY --from=poetry ${POETRY_HOME} ${POETRY_HOME}

# Add Poetry to PATH
ENV PATH="${POETRY_HOME}/bin:${PATH}"

# Copy dependencies
COPY pyproject.toml poetry.lock README.md .

# Validate the project is properly configured
RUN poetry check

# Install dependencies
RUN poetry install --no-interaction

# Copy application
COPY . .

# Run application
EXPOSE 1080
CMD ["poetry", "run", "socks-router"]
