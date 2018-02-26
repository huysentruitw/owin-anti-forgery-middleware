/*
 * Copyright 2018 Huysentruit Wouter
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Owin;

namespace OwinAntiForgeryMiddleware
{
    internal sealed class AntiForgeryMiddleware : OwinMiddleware
    {
        private readonly AntiForgeryMiddlewareOptions _options;

        public AntiForgeryMiddleware(OwinMiddleware next, AntiForgeryMiddlewareOptions options)
            : base(next)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _options.Validate();
        }

        public override async Task Invoke(IOwinContext context)
        {
            if (context.Request.Method == "GET" && context.Request.Path.Equals(_options.TokenRequestEndpoint))
            {
                await context.Response.WriteAsync(_options.ExpectedTokenExtractor(context));
                return;
            }

            if (_options.SafeMethods?.Contains(context.Request.Method) ?? false)
            {
                await Next.Invoke(context);
                return;
            }

            if (_options.SafePaths != null && _options.SafePaths.Contains(context.Request.Path))
            {
                await Next.Invoke(context);
                return;
            }

            if (context.Authentication.User?.Identities != null && (_options.SafeAuthenticationTypes?.Any() ?? false))
            {
                var safeAuthenticationTypes = context.Authentication.User.Identities.Select(x => x.AuthenticationType)
                    .Intersect(_options.SafeAuthenticationTypes);

                if (safeAuthenticationTypes.Any())
                {
                    await Next.Invoke(context);
                    return;
                }
            }

            if (context.Request.IsSecure && _options.RefererRequiredForSecureRequests)
            {
                var referer = context.Request.Headers.Get("Referer");
                if (string.IsNullOrEmpty(referer))
                {
                    context.Response.StatusCode = _options.FailureStatusCode;
                    await context.Response.WriteAsync("Referer missing in secure request");
                    return;
                }
            }

            var expectedToken = _options.ExpectedTokenExtractor(context);
            if (string.IsNullOrEmpty(expectedToken))
            {
                context.Response.StatusCode = _options.FailureStatusCode;
                await context.Response.WriteAsync("Could not extract expected anti-forgery token");
                return;
            }

            var actualToken = context.Request.Headers.Get(_options.HeaderName);
            if (string.IsNullOrEmpty(actualToken))
            {
                if (_options.FormContentTypes?.Contains(context.Request.ContentType) ?? false)
                {
                    var form = await context.Request.ReadFormAsync();
                    var tokenFields = form.GetValues(_options.FormFieldName);
                    actualToken = tokenFields?[0];
                    if (string.IsNullOrEmpty(actualToken))
                    {
                        context.Response.StatusCode = _options.FailureStatusCode;
                        await context.Response.WriteAsync($"No anti-forgery token found in form field {_options.FormFieldName}");
                        return;
                    }
                }
                else
                {
                    context.Response.StatusCode = _options.FailureStatusCode;
                    await context.Response.WriteAsync($"No anti-forgery token found in {_options.HeaderName} header");
                    return;
                }
            }

            if (!actualToken.Equals(expectedToken))
            {
                context.Response.StatusCode = _options.FailureStatusCode;
                await context.Response.WriteAsync("Invalid anti-forgery token");
                return;
            }

            await Next.Invoke(context);
        }
    }
}
