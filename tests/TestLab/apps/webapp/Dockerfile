FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY WebApp.csproj ./
RUN dotnet restore WebApp.csproj
COPY Program.cs ./
RUN dotnet publish WebApp.csproj -c Release --no-restore -o /out

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /out/ ./
USER app
EXPOSE 8080 8443
ENTRYPOINT ["dotnet", "WebApp.dll"]
