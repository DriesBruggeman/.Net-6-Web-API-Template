using Microsoft.EntityFrameworkCore;
using RENAME_TO_PROJECT_NAME.Data.Entities;
using RENAME_TO_PROJECT_NAME.Data;
using Microsoft.AspNetCore.Identity;
using RENAME_TO_PROJECT_NAME.Services;
using RENAME_TO_PROJECT_NAME.Data.Seeds;
using RENAME_TO_PROJECT_NAME.Repositories;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;
using System.Reflection;
using Microsoft.Extensions.FileProviders;
using NLog.Web;
using RENAME_TO_PROJECT_NAME.Models;

var builder = WebApplication.CreateBuilder(args);
// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    // Set the comments path for the Swagger JSON and UI.
    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    c.IncludeXmlComments(xmlPath);
});

var serverVersion = new MySqlServerVersion(new Version(8, 0, 21));

builder.Services.AddDbContext<AppDbContext>(options => {
    //options.UseMySql(builder.Configuration.GetConnectionString("QrWalletContext"), serverVersion);
    options.UseSqlite("Filename=MyDatabase.db");
});

builder.Services.AddIdentity<User, Role>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddTokenProvider<DataProtectorTokenProvider<User>>(TokenOptions.DefaultProvider);

builder.Services.AddControllers().AddJsonOptions(options => {
    options.JsonSerializerOptions.PropertyNamingPolicy = null;
});

var appSettingsSection = builder.Configuration.GetSection("AppSettings");
builder.Services.Configure<AppSettings>(appSettingsSection);

var appSettings = appSettingsSection.Get<AppSettings>();
var key = Encoding.ASCII.GetBytes(appSettings.Secret);
builder.Services.AddAuthentication(x =>
{
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(x =>
{
    x.RequireHttpsMetadata = false;
    x.SaveToken = true;
    x.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false,
        // Set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
        ClockSkew = TimeSpan.Zero
    };
    x.Events = new JwtBearerEvents()
    {
        OnChallenge = context =>
        {
            context.HandleResponse();
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";

            // Ensure we always have an error and error description.
            if (string.IsNullOrEmpty(context.Error))
            {
                context.Error = "invalid_token";
            }
            if (string.IsNullOrEmpty(context.ErrorDescription))
            {
                context.ErrorDescription = "This request requires a valid JWT access token to be provided";
            }

            // Add some extra context for expired tokens.
            if (context.AuthenticateFailure != null && context.AuthenticateFailure.GetType() ==
                typeof(SecurityTokenExpiredException))
            {
                var authenticationException = context.AuthenticateFailure as SecurityTokenExpiredException;
                context.Response.Headers.Add("x-token-expired",
                    authenticationException.Expires.ToString("o"));
                context.Error = "expired_token";
                context.ErrorDescription =
                    $"The token expired on {authenticationException.Expires.ToString("o")}";
            }

            return context.Response.WriteAsync(JsonSerializer.Serialize(new
            {
                error = context.Error,
                error_description = context.ErrorDescription
            }));
        }
    };
});

builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IRoleRepository, RoleRepository>();

builder.Services.AddScoped<IMailService, MailService>();

builder.Services.AddCors(options =>
{
    options.AddPolicy(name: "QR-CORS",
        builder =>
        {
            builder.WithOrigins(appSettings.AllowedCorsHosts).AllowCredentials().AllowAnyHeader().AllowAnyMethod();
        });
});

builder.Logging.SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Trace);
builder.Host.UseNLog();

var app = builder.Build();

if (true)
{
    using (var scope = app.Services.CreateScope())
    {
        var services = scope.ServiceProvider;
        try
        {
            InitDb.Init(services);
            RoleSeeder.Seed(services);
            UserSeeder.Seed(services);
        }
        catch (Exception ex)
        {
            var logger = services.GetRequiredService<ILogger<Program>>();
            logger.LogError(ex, "An error occurred while seeding the database.");
        }
    }
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

//app.UseHttpsRedirection();

app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(
           Path.Combine(builder.Environment.ContentRootPath, "StaticFiles/Images")),
    RequestPath = "/images"
});

app.UseRouting();

app.UseCors("QR-CORS");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
