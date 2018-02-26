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

namespace OwinAntiForgeryMiddleware
{
    public sealed class AntiForgeryMiddlewareOptions
    {
        public static class Defaults
        {
            public static readonly int ExpectedTokenMissingStatusCode = 401;
            public static readonly int FailureStatusCode = 400;
            public static readonly string[] FormContentTypes = { "application/x-www-form-urlencoded", "multipart/form-data" };
            public static readonly string FormFieldName = "csrf_token";
            public static readonly string HeaderName = "X-CSRF-Token";
            public static readonly bool RefererRequiredForSecureRequests = true;
            public static readonly string[] SafeMethods = { "GET", "HEAD", "OPTIONS", "TRACE" };
            public static readonly PathString TokenRequestEndpoint = new PathString("/auth/token");
        }

        public Func<IOwinContext, string> ExpectedTokenExtractor { get; set; }
        public int ExpectedTokenMissingStatusCode { get; set; } = Defaults.ExpectedTokenMissingStatusCode;
        public int FailureStatusCode { get; set; } = Defaults.FailureStatusCode;

        public string[] FormContentTypes { get; set; } = Defaults.FormContentTypes;
        public string FormFieldName { get; set; } = Defaults.FormFieldName;
        public string HeaderName { get; set; } = Defaults.HeaderName;
        public bool RefererRequiredForSecureRequests { get; set; } = Defaults.RefererRequiredForSecureRequests;
        public string[] SafeAuthenticationTypes { get; set; }
        public string[] SafeMethods { get; set; } = Defaults.SafeMethods;
        public PathString[] SafePaths { get; set; }
        public PathString TokenRequestEndpoint { get; set; } = Defaults.TokenRequestEndpoint;

        public void Validate()
        {
            if (ExpectedTokenExtractor == null) throw new ArgumentNullException(nameof(ExpectedTokenExtractor));
            if (string.IsNullOrEmpty(FormFieldName)) throw new ArgumentNullException(nameof(FormFieldName));
            if (string.IsNullOrEmpty(HeaderName)) throw new ArgumentNullException(nameof(HeaderName));
        }
    }
}
