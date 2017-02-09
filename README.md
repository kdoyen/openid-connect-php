# PHP OpenID Connect Basic Client

(This package is a fork of [rask/openid-connect-php][3].)

A simple library that allows an application to authenticate a user
through the basic OpenID Connect flow. This library hopes to encourage
OpenID Connect use by making it simple enough for a developer with
little knowledge of the OpenID Connect protocol to setup authentication.

A special thanks goes to Justin Richer and Amanda Anganes for their help
and support of the protocol.

This package was originally created by [Michael Jett][2] and extensively modified by
[Otto Rask][3].

## Requirements

1.  PHP 5.4 or greater
2.  CURL extension
3.  JSON extension

## Install

Add the package repository to your composer.json repositories

```json
"repositories": [
    {
        "type": "vcs",
        "url": "https://github.com/kdoyen/openid-connect-php.git"
    }
]
```

Install library using composer

```sh
composer require kdoyen/openid-connect-php
```

Then include composer autoloader

```php
<?php

require '/vendor/autoload.php';
```

## Example 1: Basic Client

```php
<?php

use OpenIdConnectClient\OpenIdConnectClient;

$oidc = new OpenIDConnectClient([
        'provider_url' => 'https://id.provider.com/',
        'client_id' => 'ClientIDHere',
        'client_secret' => 'ClientSecretHere'
    ]);

$oidc->authenticate();
$name = $oidc->requestUserInfo('given_name');
```

[See openid spec for available user attributes][1].

## Example 2: Dynamic Registration

```php
<?php

use OpenIdConnectClient\OpenIdConnectClient;

$oidc = new OpenIDConnectClient([
        'provider_url' => 'https://id.provider.com/'
    ]);

$oidc->register();
$client_id = $oidc->getClientID();
$client_secret = $oidc->getClientSecret();
```

Be sure to add logic to store the client id and client secret inside
your application.

## Example 3: Network and Security

```php
<?php

// Configure a proxy
$oidc->setHttpProxy('http://my.proxy.com:80/');

// Configure a cert
$oidc->setCertPath('/path/to/my.cert');
```

## Example 4: Request Client Credentials Token

```php
<?php

use OpenIdConnectClient\OpenIdConnectClient;

$oidc = new OpenIDConnectClient([
        'provider_url' => 'https://id.provider.com/',
        'client_id' => 'ClientIDHere',
        'client_secret' => 'ClientSecretHere'
    ]);

$oidc->providerConfigParam([
    'token_endpoint' => 'https://id.provider.com/connect/token'
]);

$oidc->addScope('my_scope');

// This assumes success (to validate check if the access_token
// property is there and a valid JWT):
$clientCredentialsToken = $oidc->requestClientCredentialsToken()->access_token;
```

## Example 5: Token Introspection

```php
<?php

use OpenIdConnectClient\OpenIdConnectClient;

$oidc = new OpenIDConnectClient([
        'provider_url' => 'https://id.provider.com/',
        'client_id' => 'ClientIDHere',
        'client_secret' => 'ClientSecretHere'
    ]);

// Provide access token to introspect.
// Can take an optional second parameter to set the token_type_hint.
$introspectionResponse = $oidc->introspectToken('provided_access_token');

// Check if the response/token is active and valid (based on exp and nbf).
$introspectionResponse->isActive();

// Get a list of allowed scopes.
$scopeArray = $introspectionResponse->getScopes();

// Simple boolean response if response has scope provided.
$introspectionResponse->hasScope('profile');
```

### Todo

- Dynamic registration does not support registration auth tokens and endpoints.
- Re-factor/replace $_SESSION usage.
- Re-factor/complete test coverage.

## License & authors information

This package is licensed with Apache License 2.0.

-   This package was [originally created by Michael Jett (jumbojett)][2] from MITRE
-   JWT signature verification support by Jonathan Reed <jdreed@mit.edu>.
-   Major refactoring/updates by [Otto Rask (rask)][3]

  [1]: http://openid.net/specs/openid-connect-basic-1_0-15.html#id_res
  [2]: https://github.com/jumbojett/OpenID-Connect-PHP
  [3]: https://github.com/rask/openid-connect-php
