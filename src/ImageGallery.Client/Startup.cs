using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using ImageGallery.Client.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace ImageGallery.Client
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
            // Add framework services.
            services.AddMvc();

            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            // https://docs.microsoft.com/en-us/aspnet/core/migration/1x-to-2x/identity-2x
            // https://stackoverflow.com/questions/45742034/asp-net-core-2-0-argumentexception-options-clientid-must-be-provided
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(options =>
                {
                    options.AccessDeniedPath = "/Authorization/AccessDenied";
                })
            .AddOpenIdConnect(options =>
                {
                    options.Authority = "https://localhost:44303/";
                    options.RequireHttpsMetadata = true;
                    options.ClientId = "imagegalleryclient";
                    options.ResponseType = "code id_token";
                    options.Scope.Add("openid");
                    options.Scope.Add("profile");
                    options.Scope.Add("address");
                    //options.CallbackPath = new PathString();
                    //options.SignedOutCallbackPath = new PathString("");
                    options.SignInScheme = "Cookies";
                    options.SaveTokens = true;
                    options.ClientSecret = "secret";
                    options.GetClaimsFromUserInfoEndpoint = true;
                    options.Events = new OpenIdConnectEvents()
                    {
                        OnTokenValidated = tokenValidatedContext =>
                        {
                            var identity = tokenValidatedContext.Principal.Identity as ClaimsIdentity;
                            var subjectClaim = identity.Claims.FirstOrDefault(z => z.Type == "sub");
                            var newClaimsIdentity = new ClaimsIdentity(
                                tokenValidatedContext.Scheme.Name, "given_name", "role");
                            newClaimsIdentity.AddClaim(subjectClaim);

                            tokenValidatedContext.Principal = new ClaimsPrincipal(newClaimsIdentity);

                            return Task.FromResult(0);
                        },
                        OnUserInformationReceived = userInformationReceivedContext =>
                        {
                            userInformationReceivedContext.User.Remove("address");
                            return Task.FromResult(0);
                        }
                    };
                });

            // register an IHttpContextAccessor so we can access the current
            // HttpContext in services by injecting it
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            // register an IImageGalleryHttpClient
            services.AddScoped<IImageGalleryHttpClient, ImageGalleryHttpClient>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Shared/Error");
            }

            app.UseAuthentication();
            
            app.UseStaticFiles();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Gallery}/{action=Index}/{id?}");
            });
        }         
    }
}
