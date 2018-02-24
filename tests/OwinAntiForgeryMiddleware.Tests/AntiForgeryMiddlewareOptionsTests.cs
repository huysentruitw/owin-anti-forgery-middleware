using System;
using NUnit.Framework;

namespace OwinAntiForgeryMiddleware.Tests
{
    [TestFixture]
    public class AntiForgeryMiddlewareOptionsTests
    {
        [Test]
        public void Validate_ExpectedTokenExtractorIsNull_ShouldThrowException()
        {
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = null };
            var ex = Assert.Throws<ArgumentNullException>(() => options.Validate());
            Assert.That(ex.ParamName, Is.EqualTo("ExpectedTokenExtractor"));
        }

        [Test]
        public void Validate_FormFieldNameIsNullOrEmpty_ShouldThrowException()
        {
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => string.Empty, FormFieldName = null };
            var ex = Assert.Throws<ArgumentNullException>(() => options.Validate());
            Assert.That(ex.ParamName, Is.EqualTo("FormFieldName"));

            options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => string.Empty, FormFieldName = string.Empty };
            ex = Assert.Throws<ArgumentNullException>(() => options.Validate());
            Assert.That(ex.ParamName, Is.EqualTo("FormFieldName"));
        }

        [Test]
        public void Validate_HeaderNameIsNullOrEmpty_ShouldThrowException()
        {
            var options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => string.Empty, HeaderName = null };
            var ex = Assert.Throws<ArgumentNullException>(() => options.Validate());
            Assert.That(ex.ParamName, Is.EqualTo("HeaderName"));

            options = new AntiForgeryMiddlewareOptions { ExpectedTokenExtractor = _ => string.Empty, HeaderName = string.Empty };
            ex = Assert.Throws<ArgumentNullException>(() => options.Validate());
            Assert.That(ex.ParamName, Is.EqualTo("HeaderName"));
        }
    }
}
