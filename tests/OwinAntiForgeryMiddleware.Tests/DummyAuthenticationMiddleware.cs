using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace OwinAntiForgeryMiddleware.Tests
{
    internal class DummyJwtMiddlewareOptions : Microsoft.Owin.Security.AuthenticationOptions
    {
        public DummyJwtMiddlewareOptions(string authenticationType)
            : base(authenticationType)
        {
        }
    }

    internal class DummyJwtMiddlewareHandler : AuthenticationHandler<DummyJwtMiddlewareOptions>
    {
        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
            => Task.FromResult(new AuthenticationTicket(new ClaimsIdentity(new[]
            {
                new Claim("sub", "test")
            }, Options.AuthenticationType), new AuthenticationProperties()));
    }

    internal class DummyJwtMiddleware : AuthenticationMiddleware<DummyJwtMiddlewareOptions>
    {
        public DummyJwtMiddleware(OwinMiddleware next, DummyJwtMiddlewareOptions options)
            : base(next, options)
        {
        }

        protected override AuthenticationHandler<DummyJwtMiddlewareOptions> CreateHandler()
            => new DummyJwtMiddlewareHandler();
    }
}