# OWIN Anti-Forgery (CSRF) middleware

[![Build status](https://ci.appveyor.com/api/projects/status/0dbfw8s2iyvvegfh/branch/master?svg=true)](https://ci.appveyor.com/project/huysentruitw/owin-anti-forgery-middleware/branch/master)

OWIN middleware for extracting and validating anti-forgery (CSRF) token in requests.

This middleware validates an incoming CSRF token in a request header against the expected CSRF token stored in a HttpOnly cookie.

When a request is made without expected CSRF token cookie, a new token will be generated and appended as HttpOnly cookie to the response.

As a consequence, the first request within each browser session should always be a safe http method (preferably a GET) as a POST without CSRF token will be blocked.

This middleware also exposes an endpoint from which the client can get the CSRF token. For each non-safe request method (configurable), like POST/DELETE/PUT/..., the client needs to pass the CSRF token as a header or form value (header name and form field name is configurable).

If the CSRF token is missing or doesn't match, a configurable failure code will be returned to the client.

You can also configure the middleware to ignore certain authentication types, f.e. if you use both OAuth2 and Cookie authentication in a single application, you may want to exclude OAuth2 authentication from anti-forgery as the OAuth2 access-token in the Authorization header makes a CSRF token redundant.

# Get it on NuGet

    PM> Install-Package OwinAntiForgeryMiddleware

# Register the middleware

In its simplest form, no additional options need to be passed as the defaults will fit for most projects:

```C#
public class Startup
{
    public void Configuration(IAppBuilder app)
    {
        app.UseCookieAuthenticationMiddleware(...);

        app.UseAntiForgeryMiddleware(new AntiForgeryMiddlewareOptions());

        // other middleware registrations...
        app.UseWebApi();
    }
}
```
