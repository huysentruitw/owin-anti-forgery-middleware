using System;
using NUnit.Framework;

namespace OwinAntiForgeryMiddleware.Tests
{
    [TestFixture]
    public class AntiForgeryMiddlewareOptionsTests
    {
        [Test]
        public void Validate_CookieDataProtectorIsNull_ShouldThrowException()
        {
            var options = new AntiForgeryMiddlewareOptions { CookieDataProtector = null };
            var ex = Assert.Throws<ArgumentNullException>(() => options.Validate());
            Assert.That(ex.ParamName, Is.EqualTo("CookieDataProtector"));
        }

        [Test]
        public void Validate_CookieNameIsNullOrEmpty_ShouldThrowException()
        {
            var options = new AntiForgeryMiddlewareOptions { CookieName = null };
            var ex = Assert.Throws<ArgumentNullException>(() => options.Validate());
            Assert.That(ex.ParamName, Is.EqualTo("CookieName"));

            options = new AntiForgeryMiddlewareOptions { CookieName = string.Empty };
            ex = Assert.Throws<ArgumentNullException>(() => options.Validate());
            Assert.That(ex.ParamName, Is.EqualTo("CookieName"));
        }

        [Test]
        public void Validate_ExpectedTokenFactoryIsNull_ShouldThrowException()
        {
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenFactory = null };
            var ex = Assert.Throws<ArgumentNullException>(() => options.Validate());
            Assert.That(ex.ParamName, Is.EqualTo("ExpectedTokenFactory"));
        }

        [Test]
        public void Validate_FormFieldNameIsNullOrEmpty_ShouldThrowException()
        {
            var options = new AntiForgeryMiddlewareOptions { FormFieldName = null };
            var ex = Assert.Throws<ArgumentNullException>(() => options.Validate());
            Assert.That(ex.ParamName, Is.EqualTo("FormFieldName"));

            options = new AntiForgeryMiddlewareOptions { FormFieldName = string.Empty };
            ex = Assert.Throws<ArgumentNullException>(() => options.Validate());
            Assert.That(ex.ParamName, Is.EqualTo("FormFieldName"));
        }

        [Test]
        public void Validate_HeaderNameIsNullOrEmpty_ShouldThrowException()
        {
            var options = new AntiForgeryMiddlewareOptions { HeaderName = null };
            var ex = Assert.Throws<ArgumentNullException>(() => options.Validate());
            Assert.That(ex.ParamName, Is.EqualTo("HeaderName"));

            options = new AntiForgeryMiddlewareOptions { HeaderName = string.Empty };
            ex = Assert.Throws<ArgumentNullException>(() => options.Validate());
            Assert.That(ex.ParamName, Is.EqualTo("HeaderName"));
        }
    }
}
