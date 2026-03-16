FROM registry.fedoraproject.org/fedora-minimal:43

RUN microdnf install -y python3.14 python3.14-pip && \
    microdnf clean all

WORKDIR /app

COPY pyproject.toml .
RUN python3.14 -m pip install --break-system-packages .

COPY src/ src/
RUN python3.14 -m pip install --break-system-packages -e .

ENTRYPOINT ["waingro"]
CMD ["--help"]
