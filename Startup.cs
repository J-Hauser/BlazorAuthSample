using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Linq.Expressions;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Http;
using System.Net.Http;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Components.Server;
using System.Threading;
using Microsoft.AspNetCore.Mvc;
using AuthSample.Pages.Security;

namespace AuthSample
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            //Authentication
            //services.Configure<CookiePolicyOptions>(options =>
            //{
            //    options.CheckConsentNeeded = context => true;
            //    options.MinimumSameSitePolicy = SameSiteMode.None;
            //});
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie();

            services.AddHttpContextAccessor();
            services.AddScoped<HttpContextAccessor>();
            services.AddHttpClient();
            services.AddScoped<HttpClient>();

            services.AddRazorPages();
            services.AddServerSideBlazor();

            services.AddScoped<LoginViewModel>();
            services.Configure<AppSettings>(Configuration);
            services.AddScoped(sp => sp.GetService<IOptionsSnapshot<AppSettings>>().Value);

            //services.AddScoped<AuthenticationStateProvider, MyAuthenticationStateProvider>();
            services.AddScoped<IAuthorizationService, MyDefaultAuthorizationService>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseCookiePolicy();

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
                endpoints.MapBlazorHub();
                endpoints.MapFallbackToPage("/_Host");
            });
        }
    }

    public class MyAuthenticationStateProvider : RevalidatingServerAuthenticationStateProvider
    {
        private Task<AuthenticationState> _authTask;

        protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(30);

        public MyAuthenticationStateProvider(ILoggerFactory loggerFactory) : base (loggerFactory)
        {
            this.AuthenticationStateChanged += MyAuthenticationStateProvider_AuthenticationStateChanged;   
        }

        private void MyAuthenticationStateProvider_AuthenticationStateChanged(Task<AuthenticationState> task)
        {
            _authTask = task;
        }

        public override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            return _authTask; 
        }

        protected override Task<bool> ValidateAuthenticationStateAsync(AuthenticationState authenticationState, CancellationToken cancellationToken)
        {
            return Task.FromResult(true);
        }
    }

    public class MyDefaultAuthorizationService : IAuthorizationService
    {
        private readonly AuthorizationOptions _options;
        private readonly IAuthorizationHandlerContextFactory _contextFactory;
        private readonly IAuthorizationHandlerProvider _handlers;
        private readonly IAuthorizationEvaluator _evaluator;
        private readonly IAuthorizationPolicyProvider _policyProvider;
        private readonly ILogger _logger;

        /// <summary>
        /// Creates a new instance of <see cref="DefaultAuthorizationService"/>.
        /// </summary>
        /// <param name="policyProvider">The <see cref="IAuthorizationPolicyProvider"/> used to provide policies.</param>
        /// <param name="handlers">The handlers used to fulfill <see cref="IAuthorizationRequirement"/>s.</param>
        /// <param name="logger">The logger used to log messages, warnings and errors.</param>  
        /// <param name="contextFactory">The <see cref="IAuthorizationHandlerContextFactory"/> used to create the context to handle the authorization.</param>  
        /// <param name="evaluator">The <see cref="IAuthorizationEvaluator"/> used to determine if authorization was successful.</param>  
        /// <param name="options">The <see cref="AuthorizationOptions"/> used.</param>  
        public MyDefaultAuthorizationService(IAuthorizationPolicyProvider policyProvider, IAuthorizationHandlerProvider handlers, ILogger<DefaultAuthorizationService> logger, IAuthorizationHandlerContextFactory contextFactory, IAuthorizationEvaluator evaluator, IOptions<AuthorizationOptions> options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }
            if (policyProvider == null)
            {
                throw new ArgumentNullException(nameof(policyProvider));
            }
            if (handlers == null)
            {
                throw new ArgumentNullException(nameof(handlers));
            }
            if (logger == null)
            {
                throw new ArgumentNullException(nameof(logger));
            }
            if (contextFactory == null)
            {
                throw new ArgumentNullException(nameof(contextFactory));
            }
            if (evaluator == null)
            {
                throw new ArgumentNullException(nameof(evaluator));
            }

            _options = options.Value;
            _handlers = handlers;
            _policyProvider = policyProvider;
            _logger = logger;
            _evaluator = evaluator;
            _contextFactory = contextFactory;
        }

        /// <summary>
        /// Checks if a user meets a specific set of requirements for the specified resource.
        /// </summary>
        /// <param name="user">The user to evaluate the requirements against.</param>
        /// <param name="resource">The resource to evaluate the requirements against.</param>
        /// <param name="requirements">The requirements to evaluate.</param>
        /// <returns>
        /// A flag indicating whether authorization has succeeded.
        /// This value is <value>true</value> when the user fulfills the policy otherwise <value>false</value>.
        /// </returns>
        public async Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object resource, IEnumerable<IAuthorizationRequirement> requirements)
        {
            if (requirements == null)
            {
                throw new ArgumentNullException(nameof(requirements));
            }

            var authContext = _contextFactory.CreateContext(requirements, user, resource);
            var handlers = await _handlers.GetHandlersAsync(authContext);
            foreach (var handler in handlers)
            {
                await handler.HandleAsync(authContext);
                if (!_options.InvokeHandlersAfterFailure && authContext.HasFailed)
                {
                    break;
                }
            }

            var result = _evaluator.Evaluate(authContext);
            if (result.Succeeded)
            {
                _logger.LogInformation("User Authorized");
            }
            else
            {
                _logger.LogInformation("User not Authorized");
            }
            return result;
        }

        /// <summary>
        /// Checks if a user meets a specific authorization policy.
        /// </summary>
        /// <param name="user">The user to check the policy against.</param>
        /// <param name="resource">The resource the policy should be checked with.</param>
        /// <param name="policyName">The name of the policy to check against a specific context.</param>
        /// <returns>
        /// A flag indicating whether authorization has succeeded.
        /// This value is <value>true</value> when the user fulfills the policy otherwise <value>false</value>.
        /// </returns>
        public async Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object resource, string policyName)
        {
            if (policyName == null)
            {
                throw new ArgumentNullException(nameof(policyName));
            }

            var policy = await _policyProvider.GetPolicyAsync(policyName);
            if (policy == null)
            {
                throw new InvalidOperationException($"No policy found: {policyName}.");
            }
            return await this.AuthorizeAsync(user, resource, policy);
        }
    }
}
