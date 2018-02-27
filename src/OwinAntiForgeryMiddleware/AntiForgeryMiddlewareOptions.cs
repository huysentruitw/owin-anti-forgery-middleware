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
using Microsoft.Owin;
using Microsoft.Owin.Security.DataProtection;

namespace OwinAntiForgeryMiddleware
{
    public sealed class AntiForgeryMiddlewareOptions
    {
        public static class Defaults
        {
            public static readonly IDataProtector CookieDataProtector = new DpapiDataProtectionProvider(typeof(AntiForgeryMiddleware).Namespace).Create(nameof(AntiForgeryMiddleware), "v1");
            public static readonly string CookieName = "CSRF";
            public static readonly Func<string> ExpectedTokenFactory = () => Guid.NewGuid().ToString("N");
            public static readonly int FailureStatusCode = 400;
            public static readonly string[] FormContentTypes = { "application/x-www-form-urlencoded", "multipart/form-data" };
            public static readonly string FormFieldName = "csrf_token";
            public static readonly string HeaderName = "X-CSRF-Token";
            public static readonly string[] SafeMethods = { "GET", "HEAD", "OPTIONS", "TRACE" };
            public static readonly PathString TokenRequestEndpoint = new PathString("/auth/token");
        }

        public IDataProtector CookieDataProtector { get; set; } = Defaults.CookieDataProtector;
        public string CookieName { get; set; } = Defaults.CookieName;
        public Func<string> ExpectedTokenFactory { get; set; } = Defaults.ExpectedTokenFactory;
        public int FailureStatusCode { get; set; } = Defaults.FailureStatusCode;
        public string[] FormContentTypes { get; set; } = Defaults.FormContentTypes;
        public string FormFieldName { get; set; } = Defaults.FormFieldName;
        public string HeaderName { get; set; } = Defaults.HeaderName;
        public Func<Uri, bool> OriginValidator { get; set; }
        public string[] SafeAuthenticationTypes { get; set; }
        public string[] SafeMethods { get; set; } = Defaults.SafeMethods;
        public PathString[] SafePaths { get; set; }
        public PathString TokenRequestEndpoint { get; set; } = Defaults.TokenRequestEndpoint;

        public void Validate()
        {
            if (CookieDataProtector == null) throw new ArgumentNullException(nameof(CookieDataProtector));
            if (string.IsNullOrEmpty(CookieName)) throw new ArgumentNullException(nameof(CookieName));
            if (ExpectedTokenFactory == null) throw new ArgumentNullException(nameof(ExpectedTokenFactory));
            if (string.IsNullOrEmpty(FormFieldName)) throw new ArgumentNullException(nameof(FormFieldName));
            if (string.IsNullOrEmpty(HeaderName)) throw new ArgumentNullException(nameof(HeaderName));
        }
    }
}
