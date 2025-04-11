This module is a plug&play assembly you can use to add to your Web API an Identity Module which can provide:
- Registration
- Login
- Authorization: based on the JWT Token get from the Login
It is build on top on **ASP.NET 8.0** and the persisting database is a **MySQL** DB but since it is build through **EntityFramework** is potentially extendible to all the repository supported
# WHAT'S NEW
## Version 1.0.0:
- First release including IdentityCore on MySQL DB
- AspNetUser Class had been extended with the following additional fields:
  - **DisplayName**
  - **DateOfBirth**
  - **Address**
  - **City**
  - **State**
  - **Country**
  - **RefreshToken**: this is used to store the refresh token for the user each time he logs in
## Previous Versions
### Version 0.0.1:
- Initial release of the JWT Token generator for .NET 8 Web API, it works as in memory only, no repository is supported
- Includes a simple controller to generate JWT tokens. The method supported are:
  - **Register** -> to register a new user
  - **Login** -> to login, it returns an accessToken and a refreshToken
  - **Refresh** -> to get a new accessToken using the refreshToken
  - **Revoke** -> to revoke the refreshToken
  - **TokenValidate** -> check if the current token is valid or not (if not you'll get a 401 Unauthorized))
# HOW TO
1. Add this project to any Web API you need to build JWT Token
2. Add the following code to your Program.cs file rigth before ```var app = builder.Build();```
```
builder.Services.AddXinJWTBearerService(builder.Configuration)
```
3. Make sure to have the token area configured in appsettings as described in the section below
# CONFIGURATIONS
## Database
- Make sure to create a ConnectionsString called ```"XinWebAPI.Auth.JWTBearer"``` in your AppSettings file
- CodeFirst: 
    - Use the command ```Add-Migration <NAME>``` to create the initial migration"
    - Use the command ```Update-Database``` to create the database on the DB specified in the connection string "AuthDb"
    - Use ```Script-Migration``` to create the SQL script for the migration
- DB Scripts: you can find the scripts in the folder ```Data/SQLScripts/MySQL``` please run them in the following sequence
    - 01.IndentityCoreEdited.sql
## AppSettings:
Define an area for the token in your appsettings.json file
```
    {
        ...
          "XinWebAPI.Auth.JWTBearer": {
            "token": {
              "key": "WGluV2ViQVBJLkpXVC5UZXN0VG9rZW4=",
              "accessTokenExpiryMinutes": 1,
              "issuer": "XinWeb",
              "audience": "PostmanClient",
              "subject": "authToken"
            }
          },
        ...
    }
```
- **key**: The key used to sign the token. This should be a long and random string BASE64. You can generate it from here https://www.base64encode.org/
- **accessTokenExpiryMinutes**: The time in minutes the token will be valid for
- **issuer**: The issuer of the token. This should be a unique identifier for your application
- **audience**: The audience for the token. This should be a unique identifier for the client application that will be using the token
- **subject**: The subject of the token. This should be a unique identifier for the user that will be using the token
