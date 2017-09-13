using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

using Casperinc.IdentityProvider.Data;
using Casperinc.IdentityProvider.Data.Models;
using Microsoft.AspNetCore.Identity;
using AspNet.Security.OpenIdConnect.Primitives;

using System.Threading;
using OpenIddict.Core;
using OpenIddict.Models;
using Casperinc.IdentityProvider.Helpers;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using NLog.Extensions.Logging;

namespace Casperinc.IdentityProvider
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            services.AddDbContext<ProviderDbContext>(options =>
            {
                // Configure the context to use MySQL Sever
                options.UseMySql(Configuration["Data:ConnectionStrings:MySQL"]);

                // Register the entity sets needed by OpenIddict.
                // Note: use the generic overload if you need
                // to replace the default OpenIddict entities.
                options.UseOpenIddict();
            });

            services.AddIdentity<User, IdentityRole>(options =>
            {
                options.User.RequireUniqueEmail = true;
                options.Password.RequireNonAlphanumeric = false;
            })
            .AddEntityFrameworkStores<ProviderDbContext>()
            .AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(options =>
            {
                options.ClaimsIdentity.UserNameClaimType = OpenIdConnectConstants.Claims.Name;
                options.ClaimsIdentity.UserIdClaimType = OpenIdConnectConstants.Claims.Subject;
                options.ClaimsIdentity.RoleClaimType = OpenIdConnectConstants.Claims.Role;
            });


            var openIdConfiguation = Configuration.GetSection("OpenIdDict").Get<OpenIdDict>();

            services.AddOpenIddict(options =>
            {
                // Register the Entity Framework stores.
                options.AddEntityFrameworkCoreStores<ProviderDbContext>();
                options.AddMvcBinders();
                options.AllowPasswordFlow();
                options.AllowRefreshTokenFlow();

                options.EnableTokenEndpoint(openIdConfiguation.TokenEndpoint);
                options.EnableIntrospectionEndpoint(openIdConfiguation.IntrospectionEndPoint);
                options.EnableAuthorizationEndpoint(openIdConfiguation.AuthorizationEndpoint);
                //options.EnableUserinfoEndpoint(Configuration["OpenIddict:UserInfoEndPoint"]);

                // Signing Certificate
                options.AddSigningCertificate(new X509Certificate2(
                    openIdConfiguation.Certificate.Path,
                    openIdConfiguation.Certificate.Password
                ));
                
            });

            services.AddAuthentication().AddOAuthValidation();

            services.AddScoped<UserSeed>();

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory, UserSeed userSeed)
        {
            loggerFactory.AddConsole();
            loggerFactory.AddNLog();
            
            if (env.IsDevelopment() || env.IsStaging())
            {
                app.UseDeveloperExceptionPage();
            }

            if (env.IsDevelopment() || env.IsStaging())
            {
                app.UseCors(builder =>
                {
                    builder.AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader();
                });
            }
            else
            {

                string[] origins = Configuration.GetSection("CORS:Origins")
                                .Get<string[]>();

                app.UseCors(builder =>
                {
                    builder.WithOrigins(origins);
                });
            }

            // seed database if needed
            try
            {
                userSeed.SeedAsync().Wait();
            }
            catch (AggregateException e)
            {
                throw new Exception(e.ToString());
            }

            app.UseAuthentication();

            app.UseMvc();

            InitializeAsync(app.ApplicationServices, CancellationToken.None).GetAwaiter().GetResult();

        }

        private async Task InitializeAsync(IServiceProvider services, CancellationToken cancellationToken)
        {
            // Create a new service scope to ensure the database context is correctly disposed when this methods returns.
            using (var scope = services.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<ProviderDbContext>();
                await context.Database.EnsureCreatedAsync();

                var manager = scope.ServiceProvider.GetRequiredService<OpenIddictApplicationManager<OpenIddictApplication>>();

                var clients = Configuration.GetSection("OpenIddict:Clients").GetChildren();


                var openIdConfiguation = Configuration.GetSection("OpenIdDict").Get<OpenIdDict>();

                foreach (var clientKvp in openIdConfiguation.Clients)
                {
                    var clientName = clientKvp.Key;
                    var client = clientKvp.Value;

                    if (await manager.FindByClientIdAsync(client.ClientId, cancellationToken) == null)
                    {
                        var application = new OpenIddictApplication
                        {
                            ClientId = client.ClientId,
                            DisplayName = client.DisplayName
                        };

                        await manager.CreateAsync(application, client.ClientSecret, cancellationToken);
                    }

                }

            }
        }



    }
}
