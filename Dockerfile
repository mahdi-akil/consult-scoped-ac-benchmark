FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    libgmp-dev \
    patchelf \
 && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade pip setuptools wheel \
 && python -m pip install gmpy2 petrelic \
 && find /usr/local/lib/python3.10/site-packages \
      -name "librelic*.so" \
      -exec patchelf --clear-execstack {} \;

WORKDIR /work
