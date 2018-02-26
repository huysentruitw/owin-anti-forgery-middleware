using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Testing;
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
            var ex = Assert.Throws<TargetInvocationException>(() => TestServer.Create(app => app.Use<AntiForgeryMiddleware>(new AntiForgeryMiddlewareOptions())));
            Assert.That((ex?.InnerException as ArgumentNullException)?.ParamName, Is.EqualTo("ExpectedTokenExtractor"));
        }

        [Test]
        public async Task AntiForgeryMiddleware_GetRequestToTokenRequestEndpoint_ShouldReturnExpectedToken()
        {
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => token, TokenRequestEndpoint = new PathString("/fancyendpoint") };

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
        public async Task AntiForgeryMiddleware_SafeMethodWithoutToken_ShouldReturnOk()
        {
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => token, SafeMethods = new[] { "GET" } };

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
        public async Task AntiForgeryMiddleware_NonSafeMethodWithoutToken_ShouldReturnBadRequest()
        {
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => token, SafeMethods = new[] { "GET" } };

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
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => token, SafePaths = new[] { new PathString("/some/safe/path") } };

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
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => token, SafePaths = new[] { new PathString("/some/safe/path") } };

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
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => token, SafeAuthenticationTypes = new[] { "jwt" } };

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
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => token, SafeAuthenticationTypes = new[] { "cookie" } };

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
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => token };

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
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => token };

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
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => token, RefererRequiredForSecureRequests = false };

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
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => token };

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
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => token };

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
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => token };

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
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => token };

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
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => token, HeaderName = "blabla" };

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
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => token, FormFieldName = "blablabla" };

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
            var token = Guid.NewGuid().ToString("N");
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => token, FailureStatusCode = (int)HttpStatusCode.Ambiguous };

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
    }
}
