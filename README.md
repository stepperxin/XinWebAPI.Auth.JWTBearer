WHAT'S NEW
------------------
Version 0.0.1:
------------------
- Initial release of the JWT Token generator for .NET 8 Web API, it works as in memory only, no repository is supported
- Includes a simple controller to generate JWT tokens. The method supported are:
  - Register -> to register a new user
  - Login -> to login, it returns an accessToken and a refreshToken
  - Refresh -> to get a new accessToken using the refreshToken
  - Revoke -> to revoke the refreshToken
  - TokenValidate -> check if the current token is valid or not (if not you'll get a 401 Unauthorized))

HOW TO
------------------
- Add this project to any Web API you need to build JWT Token 
- Add the following code to your Program.cs file rigth after the AddController

//Add JWT Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.IncludeErrorDetails = true;
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["token:issuer"],
            ValidAudience = builder.Configuration["token:audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["token:key"]))
        };
    });

- Make sure to have the token area configured in appsettings as described in the section below


CONFIGURATIONS
------------------

TOKEN CONFIGURATION
-------------------
    Define an area for the token in your appsettings.json file
    {
      ...
      "token": {
        "key": "WGluV2ViQVBJLkpXVC5UZXN0VG9rZW4=",
        "accessTokenExpiryMinutes": 1,
        "issuer": "XinWeb",
        "audience": "PostmanClient",
        "subject": "authToken"
      }
      ...
    }
    - key: The key used to sign the token. This should be a long and random string BASE64. You can generate it from here https://www.base64encode.org/
    - accessTokenExpiryMinutes: The time in minutes the token will be valid for
    - issuer: The issuer of the token. This should be a unique identifier for your application
    - audience: The audience for the token. This should be a unique identifier for the client application that will be using the token
    - subject: The subject of the token. This should be a unique identifier for the user that will be using the token