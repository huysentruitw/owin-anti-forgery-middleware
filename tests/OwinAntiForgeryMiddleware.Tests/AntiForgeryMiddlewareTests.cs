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
        private readonly Mock<IDataProtector> _dataProtectorMock = new Mock<IDataProtector>();

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            _dataProtectorMock.Setup(x => x.Protect(It.IsAny<byte[]>())).Returns<byte[]>(x => x);
            _dataProtectorMock.Setup(x => x.Unprotect(It.IsAny<byte[]>())).Returns<byte[]>(x => x);
        }

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
        public async Task AntiForgeryMiddleware_RequestExpectedToken_ShouldAppendCookie()
        {
            var options = new AntiForgeryMiddlewareOptions
            {
                SafeMethods = new[] { "GET" },
                CookieName = "Brownie",
                CookieDataProtector = _dataProtectorMock.Object,
                ExpectedTokenFactory = () => "CookieData"
            };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            {
                var response = await server.HttpClient.GetAsync("/auth/token");
                var content = await response.Content.ReadAsStringAsync();
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), content);
                Assert.That(content, Is.EqualTo("CookieData"));
                var setCookie = response.Headers.GetValues("Set-Cookie").FirstOrDefault();
                Assert.That(setCookie, Is.Not.Null, "No cookie set");
                Assert.That(setCookie, Is.EqualTo("Brownie=Q29va2llRGF0YQ%3D%3D; path=/; HttpOnly"));
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_RequestExpectedTokenTwice_NoTokenCookieInRequest_ShouldReturnTwoDifferentTokens()
        {
            var tokenQueue = new Queue<string>(new[] { "AAAA", "ZZZZ" });
            var options = new AntiForgeryMiddlewareOptions
            {
                SafeMethods = new[] { "GET" },
                CookieName = "Brownie",
                CookieDataProtector = _dataProtectorMock.Object,
                ExpectedTokenFactory = () => tokenQueue.Dequeue()
            };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                var response = await client.GetAsync("/auth/token");
                var content = await response.Content.ReadAsStringAsync();
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), content);
                Assert.That(content, Is.EqualTo("AAAA"));
                var setCookie = response.Headers.GetValues("Set-Cookie").FirstOrDefault();
                Assert.That(setCookie, Is.EqualTo("Brownie=QUFBQQ%3D%3D; path=/; HttpOnly"));

                response = await client.GetAsync("/auth/token");
                content = await response.Content.ReadAsStringAsync();
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), content);
                Assert.That(content, Is.EqualTo("ZZZZ"));
                setCookie = response.Headers.GetValues("Set-Cookie").FirstOrDefault();
                Assert.That(setCookie, Is.EqualTo("Brownie=WlpaWg%3D%3D; path=/; HttpOnly"));
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_RequestExpectedTokenTwice_WithTokenCookieInSecondRequest_ShouldReturnSameTokenTwice()
        {
            var tokenQueue = new Queue<string>(new[] { "AAAA", "ZZZZ" });
            var options = new AntiForgeryMiddlewareOptions
            {
                SafeMethods = new[] { "GET" },
                CookieName = "Brownie",
                CookieDataProtector = _dataProtectorMock.Object,
                ExpectedTokenFactory = () => tokenQueue.Dequeue()
            };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                var response = await client.GetAsync("/auth/token");
                var content = await response.Content.ReadAsStringAsync();
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), content);
                Assert.That(content, Is.EqualTo("AAAA"));
                var setCookie = response.Headers.GetValues("Set-Cookie").FirstOrDefault();
                Assert.That(setCookie, Is.EqualTo("Brownie=QUFBQQ%3D%3D; path=/; HttpOnly"));

                client.DefaultRequestHeaders.Add("Cookie", "Brownie=QUFBQQ%3D%3D");

                response = await client.GetAsync("/auth/token");
                content = await response.Content.ReadAsStringAsync();
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), content);
                Assert.That(content, Is.EqualTo("AAAA"));
                setCookie = response.Headers.GetValues("Set-Cookie").FirstOrDefault();
                Assert.That(setCookie, Is.EqualTo("Brownie=QUFBQQ%3D%3D; path=/; HttpOnly"));
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_RequestExpectedToken_ExpectedTokenFactoryReturnsNullOrEmptyString_ShouldReturnBadRequest()
        {
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenFactory = () => null };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
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
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            {
                var response = await server.HttpClient.GetAsync("/auth/token");
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                var error = await response.Content.ReadAsStringAsync();
                Assert.That(error, Is.EqualTo("ExpectedTokenFactory did not return a token"));
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_NonSafeMethodWithoutToken_ShouldReturnBadRequest()
        {
            var options = new AntiForgeryMiddlewareOptions { CookieDataProtector = _dataProtectorMock.Object, SafeMethods = new[] { "GET" } };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                client.DefaultRequestHeaders.Add("Cookie", "CSRF=YQ==");
                var response = await client.PostAsync("/test", new StringContent("content"));
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
            var options = new AntiForgeryMiddlewareOptions { CookieDataProtector = _dataProtectorMock.Object, SafePaths = new[] { new PathString("/some/safe/path") } };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                client.DefaultRequestHeaders.Add("Cookie", "CSRF=YQ==");
                var response = await client.PostAsync("/some/nonsafe/path", new StringContent(string.Empty));
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
            var options = new AntiForgeryMiddlewareOptions { CookieDataProtector = _dataProtectorMock.Object, SafeAuthenticationTypes = new[] { "cookie" } };

            using (var server = TestServer.Create(app =>
            {
                app.Use<DummyJwtMiddleware>(new DummyJwtMiddlewareOptions("jwt"));
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                client.DefaultRequestHeaders.Add("Cookie", "CSRF=YQ==");
                var response = await client.PostAsync("/test", new StringContent("content"));
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
            var options = new AntiForgeryMiddlewareOptions { CookieDataProtector = _dataProtectorMock.Object };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                client.DefaultRequestHeaders.Referrer = new Uri("https://some.referer.com");
                client.DefaultRequestHeaders.Add("Cookie", $"CSRF={Convert.ToBase64String(Encoding.UTF8.GetBytes(token))}");
                client.DefaultRequestHeaders.Add("X-CSRF-Token", token);
                var response = await client.PostAsync("https://localhost/test", new StringContent("content"));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_SecureRequestWithoutReferer_ButOptionDisabled_ShouldReturnOk()
        {
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { CookieDataProtector = _dataProtectorMock.Object, RefererRequiredForSecureRequests = false };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                client.DefaultRequestHeaders.Add("Cookie", $"CSRF={Convert.ToBase64String(Encoding.UTF8.GetBytes(token))}");
                client.DefaultRequestHeaders.Add("X-CSRF-Token", token);
                var response = await client.PostAsync("https://localhost/test", new StringContent("content"));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_TokenHeaderMatchesExpectedToken_ShouldReturnOk()
        {
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { CookieDataProtector = _dataProtectorMock.Object };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                client.DefaultRequestHeaders.Add("Cookie", $"CSRF={Convert.ToBase64String(Encoding.UTF8.GetBytes(token))}");
                client.DefaultRequestHeaders.Add("X-CSRF-Token", token);
                var response = await client.PostAsync("/test", new StringContent("content"));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_TokenHeaderDoesNotMatchExpectedToken_ShouldReturnBadRequest()
        {
            var options = new AntiForgeryMiddlewareOptions { CookieDataProtector = _dataProtectorMock.Object };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                client.DefaultRequestHeaders.Add("Cookie", "CSRF=YQ==");
                client.DefaultRequestHeaders.Add("X-CSRF-Token", "actual");
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
            var options = new AntiForgeryMiddlewareOptions { CookieDataProtector = _dataProtectorMock.Object };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                client.DefaultRequestHeaders.Add("Cookie", $"CSRF={Convert.ToBase64String(Encoding.UTF8.GetBytes(token))}");
                var response = await client.PostAsync("/test", new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("csrf_token", token) }));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_TokenFormFieldDoesNotMatchExpectedToken_ShouldReturnBadRequest()
        {
            var options = new AntiForgeryMiddlewareOptions { CookieDataProtector = _dataProtectorMock.Object };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                client.DefaultRequestHeaders.Add("Cookie", "CSRF=YQ==");
                var response = await client.PostAsync("/test", new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("csrf_token", "actual") }));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                var error = await response.Content.ReadAsStringAsync();
                Assert.That(error, Is.EqualTo("Invalid anti-forgery token"));
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_NonDefaultHeaderName_ShouldReturnOk()
        {
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { CookieDataProtector = _dataProtectorMock.Object, HeaderName = "blabla" };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                client.DefaultRequestHeaders.Add("Cookie", $"CSRF={Convert.ToBase64String(Encoding.UTF8.GetBytes(token))}");
                client.DefaultRequestHeaders.Add("blabla", token);
                var response = await client.PostAsync("/test", new StringContent("content"));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
            }
        }

        [Test]
        public async Task AntiForgeryMiddleware_NonDefaultFormFieldName_ShouldReturnOk()
        {
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { CookieDataProtector = _dataProtectorMock.Object, FormFieldName = "blablabla" };

            using (var server = TestServer.Create(app =>
            {
                app.Use<AntiForgeryMiddleware>(options);
                app.Use((ctx, next) => Task.CompletedTask);
            }))
            using (var client = server.HttpClient)
            {
                client.DefaultRequestHeaders.Add("Cookie", $"CSRF={Convert.ToBase64String(Encoding.UTF8.GetBytes(token))}");
                var response = await client.PostAsync("/test", new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("blablabla", token) }));
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
        public async Task AntiForgeryMiddleware_MissingCsrfCookie_ShouldReturnBadRequest()
        {
            var options = new AntiForgeryMiddlewareOptions { CookieDataProtector = _dataProtectorMock.Object };

            using (var server = TestServer.Create(app =>
            {
                app.UseAntiForgeryMiddleware(options);
            }))
            {
                var response = await server.HttpClient.PostAsync("/test", new StringContent(string.Empty));
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                var error = await response.Content.ReadAsStringAsync();
                Assert.That(error, Is.EqualTo("Could not extract expected anti-forgery token"));
            }
        }
    }
}
