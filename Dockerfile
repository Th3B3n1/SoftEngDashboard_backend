# Dedicated Backend Dockerfile
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY backend.csproj ./
RUN dotnet restore
COPY . ./
RUN dotnet publish backend.csproj -c Release --no-restore -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
EXPOSE 5228
ENV ASPNETCORE_HTTP_PORTS=5228
ENV ASPNETCORE_ENVIRONMENT=Production
USER $APP_UID
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "backend.dll"]

