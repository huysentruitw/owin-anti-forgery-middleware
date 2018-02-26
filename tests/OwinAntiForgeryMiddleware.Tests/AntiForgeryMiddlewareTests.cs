using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Testing;
using Moq;
using NUnit.Framework;
using Owin;

namespace OwinAntiForgeryMiddleware.Tests
{
    [TestFixture]
    public class AntiForgeryMiddlewareTests
    {
        [Test]
        public void AntiForgeryMiddleware_UseMiddleware_ShouldValidateOptions()
        {
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenFactory = null };
            var ex = Assert.Throws<TargetInvocationException>(() => TestServer.Create(app => app.Use<AntiForgeryMiddleware>(options)));
            Assert.That((ex?.InnerException as ArgumentNullException)?.ParamName, Is.EqualTo("ExpectedTokenFactory"));
        }

        [Test]
        public async Task AntiForgeryMiddleware_GetRequestToTokenRequestEndpoint_ShouldReturnExpectedToken()
        {
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenFactory = () => token, TokenRequestEndpoint = new PathString("/fancyendpoint") };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
            }))
            {
                var response = await server.HttpClient.GetAsync("/fancyendpoint");
                var actualToken = await response.Content.ReadAsStringAsync();
                Assert.That(actualToken, Is.EqualTo(token));
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_GetRequestToTokenRequestEndpoint_ExpectedTokenFactoryReturnsNullOrEmptyString_ShouldReturnBadRequest()
        {
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenFactory = () => null };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
            }))
            {
                var response = await server.HttpClient.GetAsync("/auth/token");
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                var error = await response.Content.ReadAsStringAsync();
                Assert.That(error, Is.EqualTo("ExpectedTokenFactory did not return a token"));
            }

            options = new AntiForgeryMiddlewareOptions { ExpectedTokenFactory = () => string.Empty };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
            }))
            {
                var response = await server.HttpClient.GetAsync("/auth/token");
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                var error = await response.Content.ReadAsStringAsync();
                Assert.That(error, Is.EqualTo("ExpectedTokenFactory did not return a token"));
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_SafeMethodWithoutToken_ShouldReturnOk()
        {
            var options = new AntiForgeryMiddlewareOptions { SafeMethods = new[] { "GET" } };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            {
                var response = await server.HttpClient.GetAsync("/test");
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_SafeMethodWithoutToken_ShouldAppendCookie()
        {
            var dataProtectorMock = new Mock<IDataProtector>();
            dataProtectorMock.Setup(x => x.Protect(It.IsAny<byte[]>())).Returns(Encoding.UTF8.GetBytes("CookieData"));
            var options = new AntiForgeryMiddlewareOptions
            {
                SafeMethods = new[] { "GET" },
                CookieName = "Brownie",
                CookieDataProtector = dataProtectorMock.Object
            };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            {
                var response = await server.HttpClient.GetAsync("/test");
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
                var setCookie = response.Headers.GetValues("Set-Cookie").FirstOrDefault();
                Assert.That(setCookie, Is.Not.Null, "No cookie set");
                Assert.That(setCookie, Is.EqualTo("Brownie=Q29va2llRGF0YQ%3D%3D; path=/; HttpOnly"));
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_NonSafeMethodWithoutToken_ShouldReturnBadRequest()
        {
            var options = new AntiForgeryMiddlewareOptions { SafeMethods = new[] { "GET" } };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            {
                var response = await server.HttpClient.PostAsync("/test", new StringContent("content"));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                var error = await response.Content.ReadAsStringAsync();
                Assert.That(error, Is.EqualTo("No anti-forgery token found in X-CSRF-Token header"));
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_SafePathWithoutToken_ShouldReturnOk()
        {
            var options = new AntiForgeryMiddlewareOptions { SafePaths = new[] { new PathString("/some/safe/path") } };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            {
                var response = await server.HttpClient.PostAsync("/some/safe/path", new StringContent(string.Empty));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_NonSafePathWithoutToken_ShouldReturnBadRequest()
        {
            var options = new AntiForgeryMiddlewareOptions { SafePaths = new[] { new PathString("/some/safe/path") } };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            {
                var response = await server.HttpClient.PostAsync("/some/nonsafe/path", new StringContent(string.Empty));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                var error = await response.Content.ReadAsStringAsync();
                Assert.That(error, Is.EqualTo("No anti-forgery token found in X-CSRF-Token header"));
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_SafeAuthenticationType_ShouldReturnOk()
        {
            var options = new AntiForgeryMiddlewareOptions { SafeAuthenticationTypes = new[] { "jwt" } };

            using (var server = TestServer.Create(app =>
            {
                app.Use<DummyJwtMiddleware>(new DummyJwtMiddlewareOptions("jwt"));
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            {
                var response = await server.HttpClient.PostAsync("/test", new StringContent("content"));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_NonSafeAuthenticationType_ShouldReturnBadRequest()
        {
            var options = new AntiForgeryMiddlewareOptions { SafeAuthenticationTypes = new[] { "cookie" } };

            using (var server = TestServer.Create(app =>
            {
                app.Use<DummyJwtMiddleware>(new DummyJwtMiddlewareOptions("jwt"));
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            {
                var response = await server.HttpClient.PostAsync("/test", new StringContent("content"));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                var error = await response.Content.ReadAsStringAsync();
                Assert.That(error, Is.EqualTo("No anti-forgery token found in X-CSRF-Token header"));
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_SecureRequestWithoutReferer_ShouldReturnBadRequest()
        {
            var options = new AntiForgeryMiddlewareOptions();

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            {
                var response = await server.HttpClient.PostAsync("https://localhost/test", new StringContent("content"));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                var error = await response.Content.ReadAsStringAsync();
                Assert.That(error, Is.EqualTo("Referer missing in secure request"));
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_SecureRequestWithReferer_ShouldReturnOk()
        {
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenFactory = () => token };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                client.DefaultRequestHeaders.Referrer = new Uri("https://some.referer.com");
                client.DefaultRequestHeaders.Add("X-CSRF-Token", token);
                var response = await client.PostAsync("https://localhost/test", new StringContent("content"));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_SecureRequestWithoutReferer_ButOptionDisabled_ShouldReturnOk()
        {
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenFactory = () => token, RefererRequiredForSecureRequests = false };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                client.DefaultRequestHeaders.Add("X-CSRF-Token", token);
                var response = await client.PostAsync("https://localhost/test", new StringContent("content"));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_TokenHeaderMatchesExpectedToken_ShouldReturnOk()
        {
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenFactory = () => token };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                client.DefaultRequestHeaders.Add("X-CSRF-Token", token);
                var response = await client.PostAsync("/test", new StringContent("content"));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_TokenHeaderDoesNotMatchExpectedToken_ShouldReturnBadRequest()
        {
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenFactory = () => "correcttoken" };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                client.DefaultRequestHeaders.Add("X-CSRF-Token", "wrongtoken");
                var response = await client.PostAsync("/test", new StringContent("content"));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                var error = await response.Content.ReadAsStringAsync();
                Assert.That(error, Is.EqualTo("Invalid anti-forgery token"));
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_TokenFormFieldMatchesExpectedToken_ShouldReturnOk()
        {
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenFactory = () => token };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            {
                var response = await server.HttpClient.PostAsync("/test", new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("csrf_token", token) }));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_TokenFormFieldDoesNotMatchExpectedToken_ShouldReturnBadRequest()
        {
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenFactory = () => "correcttoken" };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            {
                var response = await server.HttpClient.PostAsync("/test", new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("csrf_token", "wrongtoken") }));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                var error = await response.Content.ReadAsStringAsync();
                Assert.That(error, Is.EqualTo("Invalid anti-forgery token"));
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_NonDefaultHeaderName_ShouldReturnOk()
        {
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenFactory = () => token, HeaderName = "blabla" };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                client.DefaultRequestHeaders.Add("blabla", token);
                var response = await client.PostAsync("/test", new StringContent("content"));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_NonDefaultFormFieldName_ShouldReturnOk()
        {
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenFactory = () => token, FormFieldName = "blablabla" };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            {
                var response = await server.HttpClient.PostAsync("/test", new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("blablabla", token) }));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_NonDefaultFailedStatusCode_ShouldReturnFailedStatusCode()
        {
            var options = new AntiForgeryMiddlewareOptions { FailureStatusCode = (int)HttpStatusCode.Ambiguous };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            {
                var response = await server.HttpClient.PostAsync("/test", new StringContent("content"));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Ambiguous));
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_ExpectedTokenFactoryReturnsNullOrEmptyString_ShouldReturnBadRequest()
        {
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenFactory = () => null };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            {
                var response = await server.HttpClient.PostAsync("/test", new StringContent("content"));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                var error = await response.Content.ReadAsStringAsync();
                Assert.That(error, Is.EqualTo("ExpectedTokenFactory did not return a token"));
            }

            options = new AntiForgeryMiddlewareOptions { ExpectedTokenFactory = () => string.Empty };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            {
                var response = await server.HttpClient.PostAsync("/test", new StringContent("content"));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                var error = await response.Content.ReadAsStringAsync();
                Assert.That(error, Is.EqualTo("ExpectedTokenFactory did not return a token"));
            }
        }
    }
}
