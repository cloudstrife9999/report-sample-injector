## Report-Sample-Injector ##

Report-Sample-Injector is an addon (extension) for Google Chome and Mozilla Firefox. Its main purpose is to enhance the report capabilities of the defense-in-depth mechanism known as Content Security Policy (CSP).

CSP is an HTTP response header (**Content-Security-Policy**, or, rarely, **X-Content-Security-Policy**) standardised by the [W3C](https://www.w3.org/TR/CSP3). Essentially, it instructs web browser on how to behave when faced with certain situations (e.g., the necessity to fetch additional content, inline scripts, mixed content, etc.) while processing a web server response.

The main purpose of CSP is to offer a defense-in-depth against XSS. In its enforced version (**Content-Security-Policy**), compliant browsers must behave as specified by the CSP. In its report-only version (**Content-Security-Policy-Report-Only**), compliant web browsers do not enforce the prescribed behaviours, but generate a warning.

In both cases (enforced or not), one of the CSP directives is *report-uri*, normally followed by the URI of an endpoint accepting POST requests. When a CSP violation is detected, if *report-uri* is present and an endpoint is specified, compliant browsers will send a POST request to such endpoint specifying, among other JSON-formatted information, the  violated CSP directive.

However, violation reports do not include by default (although this is browser-dependent as of 2019) a snippet of the code that triggered the violation in the first place. It is possible to include the 'report-sample' value (apices included) for certain directives (*script-src*, *script-src-elem*, *script-src-attr*, *style-src*, *style-src-elem*, and *style-src-attr* at the moment). If a violation is encountered for a directive with 'report-sample' specified, compliant browsers include a 'script-sample' field in the JSON which is POSTed to the endpoint specified by *report-uri*. The value of 'script-sample' consists (again, this is browser-dependent until CSP level 3 is fully standardised) of the first 40 bytes of the code that triggered the violation.

The usefulness of the sample script for developers (i.e., those who check the violation reports) is that it allows to differentiate classes of violations that, without the sample, would generate the same report (e.g., inline JS handlers, inline JS scripts, and JS URIs).

Report-Sample-Injector assumes that a developer specifying an endpoint for *report-uri* is actually interested in receiving CSP reports. It also assumes that the same developer would benefit from a more fine-grained violation report. Therefore, Report-Sample-Injector looks for incoming CSP headers inside all the web responses from any server. If one or more CSP header are found, and a *report-uri*  endpoint is specified, it looks for a missing 'report-sample' within *script-src*, *script-src-elem*, *script-src-attr*, *style-src*, *style-src-elem*, and *style-src-attr*. Whenever a missing 'report-sample' is identified for one of the relevant directives, Report-Sample-Injector injects it just after the name of the directive, while leaving the remaining values untouched.

Compliant browsers will, at this point, include a 'script-sample' field in the JSON which is POSTed to the endpoint specified by *report-uri* for each encountered violation.
