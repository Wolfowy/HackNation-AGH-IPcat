# WebScan scanner agent image. Build context = repository root:
#   docker build -f src/Agent/Worker/Dockerfile -t webscan-agent:dev .
# Targets: `toolbox` (runtime + scanning tools only) and the default final stage (toolbox + agent).

# ---------- build: self-contained agent (no ICU needed, InvariantGlobalization is on) ----------
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG TARGETARCH
WORKDIR /src
COPY global.json Directory.Build.props Directory.Packages.props ./
COPY src/Shared/Contracts/WebScan.Contracts.csproj src/Shared/Contracts/
COPY src/Agent/Tools.Abstractions/WebScan.Agent.Tools.Abstractions.csproj src/Agent/Tools.Abstractions/
COPY src/Agent/Core/WebScan.Agent.Core.csproj src/Agent/Core/
COPY src/Agent/Worker/WebScan.Agent.Worker.csproj src/Agent/Worker/
RUN RID="linux-$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x64)" \
 && dotnet restore src/Agent/Worker/WebScan.Agent.Worker.csproj -r "$RID"
COPY src/Shared/Contracts/ src/Shared/Contracts/
COPY src/Agent/ src/Agent/
RUN RID="linux-$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x64)" \
 && dotnet publish src/Agent/Worker/WebScan.Agent.Worker.csproj -c Release -r "$RID" --self-contained true --no-restore -o /out

# ---------- tools-download: pinned ProjectDiscovery releases, verified against pinned SHA-256 ----------
FROM debian:bookworm-slim AS tools-download
ARG TARGETARCH
ARG NAABU_VERSION=2.7.0
ARG NAABU_SHA256_AMD64=0cc77c0ca32d2f519ffbaa7665bb0e7c88c40753ab22f03551d453a1a823e9f0
ARG NAABU_SHA256_ARM64=e88af9bbfd777e2ffab6f84696747ba74de98fafeda882c078d158a610dbd86e
ARG HTTPX_VERSION=1.12.0
ARG HTTPX_SHA256_AMD64=9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76
ARG HTTPX_SHA256_ARM64=fd7b123c1dfbc3d69f19f524e4eebcd6ec06b9a6cbd56813c76f11645197331e
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_SHA256_AMD64=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG NUCLEI_SHA256_ARM64=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07
ARG TLSX_VERSION=1.5.0
ARG TLSX_SHA256_AMD64=9458e2066d311f9d96973a6a103922fe2529ee98f1061eff464917f6f22809d4
ARG TLSX_SHA256_ARM64=04238d8df8f4e3ec4bd11608d2bcb9528287c0e8723bd57f5687818b9d71b9af
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
RUN case "$TARGETARCH" in amd64|arm64) ;; *) echo "unsupported arch: $TARGETARCH" >&2; exit 1 ;; esac; \
    ARCH_UPPER="${TARGETARCH^^}"; \
    fetch() { \
      local tool="$1" version="$2" sha="$3"; \
      local zip="${tool}_${version}_linux_${TARGETARCH}.zip"; \
      curl -fsSL -o "$zip" "https://github.com/projectdiscovery/${tool}/releases/download/v${version}/${zip}"; \
      echo "${sha}  ${zip}" | sha256sum -c -; \
      unzip -o -q "$zip" "$tool" -d /dl/bin; \
    }; \
    fetch naabu  "$NAABU_VERSION"  "$(eval echo \$NAABU_SHA256_${ARCH_UPPER})"; \
    fetch httpx  "$HTTPX_VERSION"  "$(eval echo \$HTTPX_SHA256_${ARCH_UPPER})"; \
    fetch nuclei "$NUCLEI_VERSION" "$(eval echo \$NUCLEI_SHA256_${ARCH_UPPER})"; \
    fetch tlsx   "$TLSX_VERSION"   "$(eval echo \$TLSX_SHA256_${ARCH_UPPER})"; \
    chmod 0755 /dl/bin/*

# ---------- toolbox: Debian runtime with nmap + ProjectDiscovery tools, non-root ----------
FROM debian:bookworm-slim AS toolbox
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap libpcap0.8 ca-certificates libcap2-bin libssl3 libstdc++6 zlib1g \
 && rm -rf /var/lib/apt/lists/*
COPY --from=tools-download /dl/bin/ /usr/local/bin/
# Raw sockets for SYN scans without root; tools still run as the unprivileged user.
# Only cap_net_raw: a file capability outside the container's bounding set makes exec fail with EPERM, and
# cap_net_admin is not in Docker's default set. Runtimes that drop NET_RAW must add it back (--cap-add NET_RAW).
RUN setcap cap_net_raw+eip /usr/bin/nmap \
 && setcap cap_net_raw+eip /usr/local/bin/naabu \
 && groupadd --system --gid 10001 webscan \
 && useradd --system --uid 10001 --gid webscan --home-dir /var/lib/webscan-agent --shell /usr/sbin/nologin webscan \
 && mkdir -p /var/lib/webscan-agent \
 && chown webscan:webscan /var/lib/webscan-agent \
 && chmod 0700 /var/lib/webscan-agent
USER webscan
WORKDIR /var/lib/webscan-agent

# ---------- final: agent ----------
FROM toolbox AS final
USER root
COPY --from=build /out/ /app/
COPY src/Agent/Worker/tools.d/ /app/tools.d/
ENV Agent__DataDirectory=/var/lib/webscan-agent \
    DOTNET_gcServer=0
USER webscan
WORKDIR /var/lib/webscan-agent
ENTRYPOINT ["/app/WebScan.Agent.Worker"]
