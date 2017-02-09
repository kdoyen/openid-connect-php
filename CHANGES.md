# Changes

This project was forked from rask/openid-connect-php to include the following changes:

-   Reverting PHP 7+ features to allow for PHP 5.4+ usage.
-   Implementation of token introspection for OpenID Connect based on OpenID core and RFC7662.
-   Security improvement in UrlRequest class method getCurlHandle to not disable peer certificate verification.

This project was originally forked from jumbojett/OpenID-Connect-PHP (MITRE).

Major changes since the original fork of the package include:

-   Namespacing and modularization of contents
-   PSR-2
-   Drop PHP 5 support in favor if PHP 7+
-   Style and logic adjustments according to personal preference.
