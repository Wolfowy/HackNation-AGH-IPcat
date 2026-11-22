# syntax=docker/dockerfile:1
# WebScan central server. Build context: repository root
#   docker build -f deploy/docker/server.Dockerfile -t webscan-server .

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props ./
COPY src/Shared/Contracts/ src/Shared/Contracts/
COPY src/Server/ src/Server/
# The result import reuses the agent's tool output parsers (pure library).
COPY src/Agent/Tools.Abstractions/ src/Agent/Tools.Abstractions/
COPY src/Agent/Tools.Parsers/ src/Agent/Tools.Parsers/
RUN --mount=type=cache,target=/root/.nuget/packages \
    dotnet publish src/Server/Api/WebScan.Server.Api.csproj -c Release -o /app /p:UseAppHost=false

# Alpine runtime: small, ships busybox wget for the health check; the app uses invariant globalization.
FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine
# Npgsql probes GSSAPI on Linux; without the library every connection logs a native load error.
# tzdata: Alpine ships no /usr/share/zoneinfo, so every IANA time zone except UTC (schedules, Quartz) would be "unknown".
RUN apk add --no-cache krb5-libs tzdata
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_ENVIRONMENT=Production \
    Kestrel__Endpoints__Http__Url=http://+:8080
EXPOSE 8080 8443
USER $APP_UID
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 \
    CMD wget -qO /dev/null http://127.0.0.1:8080/health/live || exit 1
ENTRYPOINT ["dotnet", "WebScan.Server.Api.dll"]
