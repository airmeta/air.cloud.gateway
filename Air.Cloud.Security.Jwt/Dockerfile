FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base

WORKDIR /tmp/app 
COPY . /tmp/app

ENV ASPNETCORE_URLS http://+:8080 
EXPOSE 8080 5295

ENTRYPOINT ["dotnet", "Air.Cloud.Security.Jwt.dll"]
RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo 'Asia/Shanghai' >/etc/timezone
