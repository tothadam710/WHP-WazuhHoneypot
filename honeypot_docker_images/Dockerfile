# --------------------------------------------------
# Cowrie SSH Honeypot - Full working Dockerfile
# --------------------------------------------------

FROM debian:bookworm-slim

LABEL maintainer="adam.toth@youremail"
LABEL description="Fully functional Cowrie honeypot with custom configuration"

# ---- Dependencies ----
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git python3 python3-venv python3-dev \
    build-essential libssl-dev libffi-dev \
    libpython3-dev unzip && \
    rm -rf /var/lib/apt/lists/*

# ---- Create Cowrie user and directories ----
RUN useradd -m -d /opt/cowrie cowrie
WORKDIR /opt/cowrie

# ---- Create virtual environment ----
RUN python3 -m venv cowrie-venv
ENV PATH="/opt/cowrie/cowrie-venv/bin:$PATH"

# ---- Clone and install Cowrie ----
RUN git clone https://github.com/cowrie/cowrie.git /opt/cowrie_src && \
    cp -r /opt/cowrie_src/* /opt/cowrie/ && rm -rf /opt/cowrie_src

# setuptools-scm fix: add fake version info before pip install
ENV SETUPTOOLS_SCM_PRETEND_VERSION_FOR_COWRIE=2.5.0

# Install Cowrie and its dependencies inside venv
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt && \
    pip install -e .

# ---- Copy your configuration ZIP ----
#COPY artifacts/cowrie_linux_output.zip /tmp/cowrie_linux_output.zip
#RUN unzip -o /tmp/cowrie_linux_output.zip -d /opt/cowrie && rm /tmp/cowrie_linux_output.zip

# ---- Permissions ----
RUN mkdir -p /opt/cowrie/log && chown -R cowrie:cowrie /opt/cowrie
USER cowrie

# ---- Expose SSH honeypot port ----
EXPOSE 2222

# Alternative safe start
CMD CMD ["cowrie", "start"]

