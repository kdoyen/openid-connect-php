<?php

namespace OpenIdConnectClient;

use phpseclib\Crypt\RSA;

/**
 * Copyright MITRE 2016
 *
 * OpenIDConnectClient for PHP5.4+
 * Original author: Michael Jett <mjett@mitre.org>
 * Work appended by: Otto Rask <ojrask@gmail.com>
 * Work appended by: Kristopher Doyen <kristopher.doyen@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

/**
 * Class OpenIDConnectClient
 *
 * Please note this class stores nonces by default in $_SESSION['openid_connect_nonce']
 * AND state in $_SESSION['openid_connect_state']
 *
 * @TODO Replace $_SESSION usage with a more portable/flexible solution.
 * @package OpenIdConnectClient
 */
class OpenIdConnectClient
{
    /**
     * Client ID used for interacting with OpenID provider.
     *
     * @access protected
     * @var string
     */
    protected $clientId;

    /*
     * Client name.
     *
     * @access protected
     * @var string
     */
    protected $clientName;

    /**
     * Client secret (password) for OpenID provider.
     *
     * @access protected
     * @var string
     */
    protected $clientSecret;

    /**
     * Provider configuration.
     *
     * @access protected
     * @var mixed[]
     */
    protected $providerConfig = [];

    /**
     * Proxy address if needed.
     *
     * @access protected
     * @var string
     */
    protected $httpProxy;

    /**
     * Absolute path to system SSL certificates.
     *
     * @access protected
     * @var string
     */
    protected $certPath;

    /**
     * Acquired access token. Used for various interactions with the provider.
     *
     * @access protected
     * @var string
     */
    protected $accessToken;

    /**
     * Redirect URL after provider has authenticated a user on their end.
     *
     * @access protected
     * @var string
     */
    protected $redirectUrl;

    /**
     * Refresh tokens are used to refresh access/session tokens.
     *
     * @access protected
     * @var string
     */
    protected $refreshToken;

    /**
     * Auth ID token.
     *
     * @access protected
     * @var string
     */
    protected $idToken;

    /**
     * Token response data.
     *
     * @access protected
     * @var string
     */
    protected $tokenResponse;

    /**
     * Scopes for interaction (e.g. what can be requested and where).
     *
     * @access protected
     * @var array
     */
    protected $scopes = [];

    /**
     * Types of responses that are available from/for provider.
     *
     * @access protected
     * @var array
     */
    protected $responseTypes = [];

    /**
     * Requested user info after a user has authenticated.
     *
     * @access protected
     * @var array
     */
    protected $userInfo = [];

    /**
     * Required and optional auhtentication parameters.
     *
     * @access protected
     * @var array
     */
    protected $authParams = [];

    /**
     * Well known OpenID provider properties from the providers dataset
     * (.well-known).
     *
     * @access protected
     * @var mixed
     */
    protected $wellKnown = false;

    /**
     * URL request class.
     *
     * @var UrlRequest
     */
    public $urlRequester;

    /**
     * OpenIdConnectClient constructor.
     *
     * @param string[] $provider_args Arguments for OIDC provider setup {
     *     @var string $provider_url
     *     @var string $client_id
     *     @var string $client_secret
     * }
     *
     * @return void
     */
    public function __construct(array $provider_args = [])
    {
        $this->urlRequester = new UrlRequest();

        $provider_url = isset($provider_args['provider_url'])
            ? $provider_args['provider_url']
            : null;

        $client_id = isset($provider_args['client_id'])
            ? $provider_args['client_id']
            : null;

        $client_secret = isset($provider_args['client_secret'])
            ? $provider_args['client_secret']
            : null;

        if ($provider_url) {
            $this->setProviderUrl($provider_url);
        }

        if ($client_id) {
            $this->clientId = $client_id;
        }

        if ($client_secret) {
            $this->clientSecret = $client_secret;
        }
    }

    /**
     * Set the OpenID provider's URL.
     *
     * @param string $provider_url
     *
     * @return void
     */
    public function setProviderUrl($provider_url)
    {
        $this->providerConfig['issuer'] = $provider_url;
    }

    /**
     * Get provider host.
     *
     * @return string
     */
    public function getProviderHost()
    {
        $url = $this->getProviderUrl();

        return preg_replace('%^(https?://[^/?]+).*$%', '$1', $url);
    }

    /**
     * Add additional response types.
     *
     * @param mixed[] $response_types
     *
     * @return void
     */
    public function addResponseTypes(array $response_types)
    {
        $this->responseTypes = array_merge($this->responseTypes, $response_types);
    }

    /**
     * Get defined response types for the client.
     *
     * @return array
     */
    public function getResponseTypes()
    {
        return $this->responseTypes;
    }

    /**
     * Authenticate a user, or then redirect to authorization.
     *
     * @throws OpenIdConnectException
     *
     * @return bool
     */
    public function authenticate()
    {
        // Do a preemptive check to see if the provider has thrown an error from a
        // previous redirect
        if (isset($_REQUEST['error'])) {
            $error_message = sprintf(
                'Error: %s Description: %s',
                $_REQUEST['error'],
                $_REQUEST['error_description']
            );

            throw new OpenIdConnectException($error_message);
        }

        // No auth redirect code available, attempt to redirect to login/authz
        if (!isset($_REQUEST['code'])) {
            $this->requestAuthorization();

            return false;
        }

        $code = $_REQUEST['code'];
        $token_json = $this->requestTokens($code);

        if (!$token_json) {
            throw new OpenIdConnectException('Unknown error, could not reach OpenID provider');
        }

        // Throw an error if the server returns one
        if (isset($token_json->error)) {
            $error_message = isset($token_json->error_description)
                ? $token_json->error_description
                : 'Got response: ' . $token_json->error;

            throw new OpenIdConnectException($error_message);
        }

        // Do an OpenID Connect session check
        if ($_REQUEST['state'] !== $this->getState()) {
            throw new OpenIdConnectException('Unable to determine session state');
        }

        // Cleanup state
        $this->unsetState();

        if (!property_exists($token_json, 'id_token')) {
            throw new OpenIdConnectException('User did not authorize openid scope.');
        }

        $claims = $this->decodeJwt($token_json->id_token, 1);

        if (!$this->canVerifySignatures()) {
            throw new OpenIdConnectException('JWT signature verification unavailable');
        }

        // Attempt JWT signature verification
        if (!$this->verifyJwtSignature($token_json->id_token)) {
            throw new OpenIdConnectException('Unable to verify signature');
        }

        // Attempt JWT claims verifications
        if (!$this->verifyJwtClaims($claims, $token_json->access_token)) {
            throw new OpenIdConnectException('Unable to verify JWT claims');
        }

        // Clean up the session a little
        $this->unsetNonce();

        // Save the full response
        $this->tokenResponse = $token_json;

        // Save the id token
        $this->idToken = $token_json->id_token;

        // Save the access token
        $this->accessToken = $token_json->access_token;

        // Save the refresh token, if we got one
        if (isset($token_json->refresh_token)) {
            $this->refreshToken = $token_json->refresh_token;
        }

        // Success!
        return true;
    }

    /**
     * It calls the end-session endpoint of the OpenID Connect provider to notify the
     * OpenID Connect provider that the end-user has logged out of the relying party
     * site (the client application).
     *
     * @param string $accessToken ID token (obtained at login)
     * @param string $redirect URL to which the RP is requesting that the End-User's
     *                         User Agent be redirected after a logout has been
     *                         performed. The value MUST have been previously
     *                         registered with the OP. Value can be empty string.
     *
     * @return void
     */
    public function signOut($accessToken, $redirect = '')
    {
        $redirect = $redirect === '' ? null : $redirect;

        $signout_endpoint = $this->getProviderConfigValue('end_session_endpoint');

        $signout_params = ['id_token_hint' => $accessToken];

        if ($redirect !== null) {
            $signout_params['post_logout_redirect_uri'] = $redirect;
        }

        $signout_endpoint .= '?' . http_build_query($signout_params, '', '&');

        $this->redirect($signout_endpoint);
    }

    /**
     * Add a scope.
     *
     * @param mixed[] $scope - example: openid, given_name, etc...
     *
     * @return void
     */
    public function addScopes(array $scope)
    {
        $this->scopes = array_merge($this->scopes, $scope);
    }

    /**
     * Get the scopes that are set for this client.
     *
     * @return array
     */
    public function getScopes()
    {
        return $this->scopes;
    }

    /**
     * Add an authentication parameter.
     *
     * @param mixed[] $param - example: prompt=login
     *
     * @return void
     */
    public function addAuthParams(array $param)
    {
        $this->authParams = array_merge($this->authParams, $param);
    }

    /**
     * Get client's auth params.
     *
     * @return array
     */
    public function getAuthParams()
    {
        return $this->authParams;
    }

    /**
     * Get's anything that we need configuration wise including endpoints, and other
     * values.
     *
     * @throws OpenIdConnectException
     * @access protected
     *
     * @param string $param Parameter to get from provider config.
     * @param mixed $default Optional. Use a default value if provider hs no value
     *                       set.
     *
     * @return mixed
     */
    protected function getProviderConfigValue($param, $default = null)
    {
        if (isset($this->providerConfig[$param])) {
            return $this->providerConfig[$param];
        }

        if (!$this->wellKnown) {
            $this->wellKnown = $this->getProviderWellKnownConfiguration();
        }

        $value = isset($this->wellKnown->{$param})
            ? $this->wellKnown->{$param}
            : false;

        if ($value) {
            $this->providerConfig[$param] = $value;
        } elseif (isset($default)) {
            // Uses default value if provided
            $this->providerConfig[$param] = $default;
        } else {
            throw new OpenIdConnectException("The provider {$param} has not been set. Make sure your provider has a well known configuration available.");
        }

        return $this->providerConfig[$param];
    }

    /**
     * Get the well-known provider config data.
     *
     * @access protected
     * @return mixed
     */
    protected function getProviderWellKnownConfiguration()
    {
        $provider_url = rtrim($this->getProviderUrl(), '/');
        $well_known_config_url = sprintf('%s%s', $provider_url, '/.well-known/openid-configuration');

        return json_decode($this->fetchUrl($well_known_config_url));
    }

    /**
     * Set the redirection URL for authentication flow.
     *
     * @param string $url
     *
     * @return void
     */
    public function setRedirectUrl($url)
    {
        if (filter_var($url, FILTER_VALIDATE_URL) !== false) {
            $this->redirectUrl = $url;
        }
    }

    /**
     * Gets the redirect URL or the URL of the current page we are on, encodes, and
     * returns it.
     *
     * @return string
     */
    public function getRedirectUrl()
    {
        // If the redirect URL has been set then return it.
        if (!empty($this->redirectUrl)) {
            return (string) $this->redirectUrl;
        }

        // Other-wise return the URL of the current page

        /**
         * Thank you
         * http://stackoverflow.com/questions/189113/how-do-i-get-current-page-full-url-in-php-on-a-windows-iis-server
         */

        /*
         * Compatibility with multiple host headers.
         * The problem with SSL over port 80 is resolved and non-SSL over port 443.
         * Support of 'ProxyReverse' configurations.
         */

        $protocol = @$_SERVER['HTTP_X_FORWARDED_PROTO']
            ?: @$_SERVER['REQUEST_SCHEME']
                ?: ((isset($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] == "on") ? "https" : "http");

        $port = @intval($_SERVER['HTTP_X_FORWARDED_PORT'])
            ?: @intval($_SERVER["SERVER_PORT"])
                ?: (($protocol === 'https') ? 443 : 80);

        $host = @explode(":", $_SERVER['HTTP_HOST'])[0]
            ?: @$_SERVER['SERVER_NAME']
                ?: @$_SERVER['SERVER_ADDR'];

        // Don't include port if it's 80 or 443 and the protocol matches
        $port = ($protocol === 'https' && $port === 443) || ($protocol === 'http' && $port === 80) ? '' : ':' . $port;

        return sprintf('%s://%s%s/%s', $protocol, $host, $port, @trim(reset(explode("?", $_SERVER['REQUEST_URI'])), '/'));
    }

    /**
     * Used for arbitrary value generation for nonces and state
     *
     * @access protected
     * @return string
     */
    protected function generateRandString()
    {
        $rand = (string) rand();

        return md5(uniqid($rand, TRUE));
    }

    /**
     * Start here. First we request authorization from the provider and then the
     * provider redirects to a wanted redirect URL.
     *
     * @access protected
     * @return void
     */
    protected function requestAuthorization()
    {
        $auth_endpoint = $this->getProviderConfigValue('authorization_endpoint');
        $response_type = 'code';

        // Generate and store a nonce in the session
        // The nonce is an arbitrary value
        $nonce = $this->setNonce($this->generateRandString());

        // State essentially acts as a session key for OIDC
        $state = $this->setState($this->generateRandString());

        $auth_params = array_merge($this->authParams, [
            'response_type' => $response_type,
            'response_mode' => 'form_post',
            'redirect_uri' => $this->getRedirectUrl(),
            'client_id' => $this->clientId,
            'nonce' => $nonce,
            'state' => $state
        ]);

        // If the client has been registered with additional scopes
        if (sizeof($this->scopes) > 0) {
            $auth_params = array_merge($auth_params, [
                'scope' => implode(' ', $this->scopes)
            ]);
        }

        // If the client has been registered with additional response types
        if (sizeof($this->responseTypes) > 0) {
            $auth_params = array_merge($auth_params, [
                'response_type' => implode(' ', $this->responseTypes)
            ]);
        }

        $auth_endpoint .= '?' . http_build_query($auth_params, '', '&');

        session_commit();

        $this->redirect($auth_endpoint);
    }

    /**
     * Requests a client credentials token
     *
     * @return mixed
     */
    public function requestClientCredentialsToken()
    {
        $token_endpoint = $this->getProviderConfigValue('token_endpoint');
        $headers = [];
        $grant_type = 'client_credentials';

        $post_data = [
            'grant_type' => $grant_type,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'scope' => implode(' ', $this->scopes)
        ];

        $post_params = http_build_query($post_data, '', '&');

        return json_decode($this->fetchUrl($token_endpoint, $post_params, $headers));
    }


    /**
     * Requests ID and Access tokens by using code.
     *
     * @access protected
     *
     * @param string $code
     *
     * @return mixed
     */
    protected function requestTokens($code)
    {
        $token_endpoint = $this->getProviderConfigValue('token_endpoint');
        $token_endpoint_auth_methods_supported = $this->getProviderConfigValue('token_endpoint_auth_methods_supported', ['client_secret_basic']);
        $headers = [];
        $grant_type = 'authorization_code';

        $token_params = [
            'grant_type' => $grant_type,
            'code' => $code,
            'redirect_uri' => $this->getRedirectUrl(),
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret
        ];

        // Consider Basic authentication if provider config is set this way
        if (in_array('client_secret_basic', $token_endpoint_auth_methods_supported)) {
            $basic_auth_header_value = base64_encode($this->clientId . ':' . $this->clientSecret);
            $headers = ['Authorization: Basic ' . $basic_auth_header_value];
            unset($token_params['client_secret']);
        }

        // Convert token params to string format
        $token_params = http_build_query($token_params);

        $token_response = json_decode($this->fetchUrl($token_endpoint, $token_params, $headers));

        return $token_response;
    }

    /**
     * Requests Access token with refresh token
     *
     * @param string $refresh_token
     *
     * @return mixed
     */
    public function refreshToken($refresh_token)
    {
        $token_endpoint = $this->getProviderConfigValue('token_endpoint');
        $grant_type = 'refresh_token';

        $token_params = [
            'grant_type' => $grant_type,
            'refresh_token' => $refresh_token,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        // Convert token params to string format
        $token_params = http_build_query($token_params, '', '&');

        $json = json_decode($this->fetchUrl($token_endpoint, $token_params));
        $this->refreshToken = $json->refresh_token;

        return $json;
    }

    /**
     * Get a key for a header from a collection of keys.
     *
     * @access protected
     * @throws OpenIdConnectException
     *
     * @param array $keys JWS keys to search from
     * @param \stdClass $header Header to match against
     *
     * @return object
     */
    protected function getKeyForHeader(array $keys, \stdClass $header)
    {
        foreach ($keys as $key) {
            if ($this->keyMatchesHeader($key, $header)) {
                return $key;
            }
        }

        if (isset($header->kid)) {
            throw new OpenIdConnectException('Unable to find a key for (algorithm, kid):' . $header->alg . ', ' . $header->kid . ')');
        }

        throw new OpenIdConnectException('Unable to find a key for RSA');
    }

    /**
     * See whether a key matches a header.
     *
     * @access protected
     *
     * @param \stdClass $key Key to check.
     * @param \stdClass $header header to use when checking.
     *
     * @return bool
     */
    protected function keyMatchesHeader(\stdClass $key, \stdClass $header)
    {
        // TODO messy, try to streamline this stuff
        $header_kid_available = isset($header->kid);
        $kid_match = $header_kid_available ? $header->kid === $key->kid : false;
        $alg_match = $header->alg === $key->alg;

        if ($key->kty === 'RSA' && (!$header_kid_available || $kid_match)) {
            return true;
        }

        if ($kid_match && $alg_match) {
            return true;
        }

        return false;
    }

    /**
     * Verify a RSA JWT signature.
     *
     * @throws OpenIdConnectException
     * @access protected
     *
     * @param string $hashtype
     * @param \stdClass $key
     * @param string $payload
     * @param string $signature
     *
     * @return bool
     */
    protected function verifyRsaJwtSignature(
       $hashtype,
        \stdClass $key,
       $payload,
       $signature
    )
    {
        if (!class_exists(RSA::class)) {
            throw new OpenIdConnectException('Crypt_RSA support unavailable.');
        }

        if (!(property_exists($key, 'n') && property_exists($key, 'e'))) {
            throw new OpenIdConnectException('Malformed key object');
        }

        // We already have base64url-encoded data, so re-encode it as regular base64
        // and use the XML key format for simplicity.
        $public_key_xml = "<RSAKeyValue>\r\n" .
            "  <Modulus>%s</Modulus>\r\n" .
            "  <Exponent>%s</Exponent>\r\n" .
            "</RSAKeyValue>";

        $public_key_xml = sprintf($public_key_xml, b64url2b64($key->n), b64url2b64($key->e));

        $rsa = new RSA();
        $rsa->setHash($hashtype);
        $rsa->loadKey($public_key_xml, RSA::PUBLIC_FORMAT_XML);
        $rsa->signatureMode = RSA::SIGNATURE_PKCS1;

        return $rsa->verify($payload, $signature);
    }

    /**
     * Verify a JWT signature.
     *
     * @throws OpenIdConnectException
     * @access protected
     *
     * @param string $jwt Encoded JWT.
     *
     * @return bool
     */
    protected function verifyJwtSignature($jwt)
    {
        $parts = explode('.', $jwt);
        $signature = Utils::base64url_decode(array_pop($parts));
        $header = json_decode(Utils::base64url_decode($parts[0]));
        $payload = implode('.', $parts);

        $jwks_uri = $this->getProviderConfigValue('jwks_uri');

        $jwks = json_decode($this->fetchUrl($jwks_uri));

        if ($jwks === null) {
            throw new OpenIdConnectException('Error decoding JSON from jwks_uri');
        }

        if (!in_array($header->alg, ['RS256', 'RS384', 'RS512'])) {
            throw new OpenIdConnectException('No support for signature type: ' . $header->alg);
        }

        $hashtype = 'sha' . substr($header->alg, 2);

        return $this->verifyRsaJwtSignature(
                $hashtype,
                $this->getKeyForHeader($jwks->keys, $header),
                $payload,
                $signature
            );
    }

    /**
     * Verify JWT claims.
     *
     * @access protected
     *
     * @param \stdClass $claims
     * @param string $accessToken Optional.
     *
     * @return bool
     */
    protected function verifyJwtClaims(\stdClass $claims, $accessToken = null)
    {
        $expected_at_hash = isset($claims->at_hash) && isset($accessToken)
            ? $this->getJwtClaimsAtHashForAccessToken($accessToken)
            : '';

        $provider_match = $claims->iss === $this->getProviderUrl();
        $client_id_match = ($claims->aud === $this->clientId) || (in_array($this->clientId, $claims->aud));
        $nonce_match = $claims->nonce === $this->getNonce();
        $claims_not_expired = !isset($claims->exp) || $claims->exp > time();
        $claims_nbf_okay = !isset($claims->nbf) || $claims->nbf < time();
        $claims_hash_match = !isset($claims->at_hash) || $claims->at_hash === $expected_at_hash;

        return ($provider_match && $client_id_match && $nonce_match && $claims_not_expired && $claims_nbf_okay && $claims_hash_match);
    }

    /**
     * When checking JWT claims and an access token is used, the hash must match.
     * This method generates the hash for an access token for checking.
     *
     * @access protected
     *
     * @param string $accessToken
     *
     * @return string
     */
    protected function getJwtClaimsAtHashForAccessToken($accessToken)
    {
        $access_token_header = $this->getAccessTokenHeader();
        $access_token_header_alg = isset($access_token_header->alg)
            ? $access_token_header->alg
            : null;

        if ($access_token_header_alg && $access_token_header_alg !== 'none') {
            $bit = substr($access_token_header_alg, 2, 3);
        } else {
            // TODO: Error case. throw exception???
            $bit = '256';
        }

        $len = ((int) $bit) / 16;
        $hash = hash('sha' . $bit, $accessToken, true);

        return $this->base64EncodeUrl(substr($hash, 0, $len));
    }

    /**
     * Safe base64 encode an URL.
     *
     * @access protected
     *
     * @param string $str URL to encode.
     *
     * @return string
     */
    protected function base64EncodeUrl($str)
    {
        $enc = base64_encode($str);
        $enc = rtrim($enc, '=');
        $enc = strtr($enc, '+/', '-_');

        return $enc;
    }

    /**
     * Decode a JWT token.
     *
     * @access protected
     *
     * @param string $jwt Encoded JWT.
     * @param int $section The section we would like to decode.
     *
     * @return \stdClass
     */
    protected function decodeJwt($jwt, $section = 0)
    {
        $parts = explode('.', $jwt);

        return json_decode(Utils::base64url_decode($parts[$section]));
    }

    /**
     * Request user information data from an OpenID provider.
     *
     * OpenID user attributes as last known when coding:
     *
     * Attribute        Type        Description
     * user_id          string      REQUIRED Identifier for the End-User at the
     *                              Issuer.
     * name             string      End-User's full name in displayable form
     *                              including all name parts, ordered according to
     *                              End-User's locale and preferences.
     * given_name       string      Given name or first name of the End-User.
     * family_name      string      Surname or last name of the End-User.
     * middle_name      string      Middle name of the End-User.
     * nickname         string      Casual name of the End-User that may or may not
     *                              be the same as the given_name. For instance, a
     *                              nickname value of Mike might be returned
     *                              alongside a given_name value of Michael.
     * profile          string      URL of End-User's profile page.
     * picture          string      URL of the End-User's profile picture.
     * website          string      URL of End-User's web page or blog.
     * email            string      The End-User's preferred e-mail address.
     * verified         boolean     True if the End-User's e-mail address has been
     *                              verified; otherwise false.
     * gender           string      The End-User's gender: Values defined by this
     *                              specification are female and male. Other values
     *                              MAY be used when neither of the defined values
     *                              are applicable.
     * birthday         string      The End-User's birthday, represented as a date
     *                              string in MM/DD/YYYY format. The year MAY be
     *                              0000, indicating that it is omitted.
     * zoneinfo         string      String from zoneinfo [zoneinfo] time zone
     *                              database. For example, Europe/Paris or
     *                              America/Los_Angeles.
     * locale           string      The End-User's locale, represented as a BCP47
     *                              [RFC5646] language tag. This is typically an
     *                              ISO 639-1 Alpha-2 [ISO639‑1] language code in
     *                              lowercase and an ISO 3166-1 Alpha-2 [ISO3166‑1]
     *                              country code in uppercase, separated by a dash.
     *                              For example, en-US or fr-CA. As a compatibility
     *                              note, some implementations have used an
     *                              underscore as the separator rather than a dash,
     *                              for example, en_US; Implementations MAY choose to
     *                              accept this locale syntax as well.
     * phone_number     string      The End-User's preferred telephone number.
     *                              E.164 [E.164] is RECOMMENDED as the format of
     *                              this Claim. For example, +1 (425) 555-1212 or
     *                              +56 (2) 687 2400.
     * address          JSON        The End-User's preferred address. The value of
     *                              the address member is a JSON [RFC4627] structure
     *                              containing some or all of the members defined in
     *                              Section 2.4.2.1.
     * updated_time     string      Time the End-User's information was last updated,
     *                              represented as a RFC 3339 [RFC3339] datetime. For
     *                              example, 2011-01-03T23:58:42+0000.
     *
     * @param string $attribute Optional. Get a single value by name.
     *
     * @return mixed
     */
    public function requestUserInfo($attribute = '')
    {
        $attribute = $attribute === '' ? null : $attribute;

        $user_info_endpoint = $this->getProviderConfigValue('userinfo_endpoint');
        $schema = 'openid';
        $user_info_endpoint .= '?schema=' . $schema;
        $auth_bearer_header_value = sprintf('Authorization: Bearer %s', $this->accessToken);

        // The accessToken has to be send in the Authorization header, so we create a
        // new array with only this header.
        $headers = [$auth_bearer_header_value];

        $user_json = json_decode($this->fetchUrl($user_info_endpoint, '', $headers));

        $this->userInfo = $user_json;

        if ($attribute === null) {
            return $this->userInfo;
        } else if (array_key_exists($attribute, $this->userInfo)) {
            return $this->userInfo->$attribute;
        }

        return null;
    }

    /**
     * Make a HTTP request.
     *
     * @throws OpenIdConnectException
     * @access protected
     *
     * @param string $url URL address to make request against.
     * @param string $post_body Optional. If this contains anything the post type
     *                          will be POST.
     * @param mixed[] $headers Optional. Extra headers to be send with the request.
     *                         Format as 'NameHeader: ValueHeader'
     *
     * @return mixed
     */
    protected function fetchUrl($url, $post_body = '', array $headers = [])
    {
        return $this->urlRequester->fetch($url, $post_body, $headers);
    }

    /**
     * Get the OpenID provider URL.
     *
     * @throws OpenIdConnectException
     * @return string
     */
    public function getProviderUrl()
    {
        if (!isset($this->providerConfig['issuer'])) {
            throw new OpenIdConnectException('The provider URL has not been set');
        }

        return $this->providerConfig['issuer'];
    }

    /**
     * Do a redirection.
     *
     * @access protected
     *
     * @param string $url URL to redirect to.
     *
     * @return void
     */
    protected function redirect($url)
    {
        header('Location: ' . $url);
        exit;
    }

    /**
     * Set a HTTP proxy to use for connections.
     *
     * @param string $httpProxy
     *
     * @return void
     */
    public function setHttpProxy($httpProxy)
    {
        $this->httpProxy = $httpProxy;
        $this->urlRequester->httpProxy = $this->httpProxy;
    }

    /**
     * Set a file system path to certificates used for connections.
     *
     * @param string $certPath
     *
     * @return void
     */
    public function setCertPath($certPath)
    {
        $this->certPath = $certPath;
        $this->urlRequester->certPath = $this->certPath;
    }

    /**
     * Use this to alter a provider's endpoints and other attributes
     *
     * @param array $array Keys and values to set.
     *
     * @return void
     */
    public function setProviderConfigParams(array $array)
    {
        $this->providerConfig = array_merge($this->providerConfig, $array);
    }

    /**
     * Set the client secret used for auth and API.
     *
     * @param string $clientSecret
     *
     * @return void
     */
    public function setClientSecret($clientSecret)
    {
        $this->clientSecret = $clientSecret;
    }

    /**
     * Set the client ID used for auth and API.
     *
     * @param string $clientId
     *
     * @return void
     */
    public function setClientId($clientId)
    {
        $this->clientId = $clientId;
    }

    /**
     * Dynamic registration.
     *
     * @throws OpenIdConnectException
     *
     * @return void
     */
    public function register()
    {
        $registration_endpoint = $this->getProviderConfigValue('registration_endpoint');

        $send_object = (object) [
            'redirect_uris' => [$this->getRedirectUrl()],
            'client_name' => $this->getClientName()
        ];

        $response = $this->fetchUrl($registration_endpoint, json_encode($send_object));

        $json_response = json_decode($response);

        if ($json_response === false) {
            throw new OpenIdConnectException('Error registering: JSON response received from the server was invalid.');
        } elseif (isset($json_response->error_description)) {
            throw new OpenIdConnectException($json_response->error_description);
        }

        $this->setClientId($json_response->client_id);

        // The OpenID Connect Dynamic registration protocol makes the client secret
        // optional and provides a registration access token and URI endpoint if it
        // is not present.

        if (!isset($json_response->client_secret)) {
            throw new OpenIdConnectException('Error registering: Please contact the OpenID Connect provider and obtain a Client ID and Secret directly from them');
        }

        $this->setClientSecret($json_response->client_secret);
    }

    /**
     * Get the client name.
     *
     * @return string
     */
    public function getClientName()
    {
        return $this->clientName;
    }

    /**
     * Set the client name.
     *
     * @param string $client_name
     *
     * @return void
     */
    public function setClientName($client_name)
    {
        $this->clientName = $client_name;
    }

    /**
     * Get the client ID.
     *
     * @return string
     */
    public function getClientId()
    {
        return $this->clientId;
    }

    /**
     * Get the client secret.
     *
     * @return string
     */
    public function getClientSecret()
    {
        return $this->clientSecret;
    }

    /**
     * Can the client verify signatures using phpseclib RSA implementation?
     *
     * @return bool
     */
    public function canVerifySignatures()
    {
        return class_exists(RSA::class);
    }

    /**
     * Get the client access token.
     *
     * @return string|null
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * Get the client's refresh token.
     *
     * @return string
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * Get auth ID token.
     *
     * @return string|null
     */
    public function getIdToken()
    {
        return $this->idToken;
    }

    /**
     * Get the access token header.
     *
     * @return object
     */
    public function getAccessTokenHeader()
    {
        return $this->decodeJwt($this->accessToken, 0);
    }

    /**
     * Get access token payload.
     *
     * @return object
     */
    public function getAccessTokenPayload()
    {
        return $this->decodeJwt($this->accessToken, 1);
    }

    /**
     * Get auth ID token header.
     *
     * @return object
     */
    public function getIdTokenHeader()
    {
        return $this->decodeJwt($this->idToken, 0);
    }

    /**
     * Get auth ID token payload.
     *
     * @return object
     */
    public function getIdTokenPayload()
    {
        return $this->decodeJwt($this->idToken, 1);
    }

    /**
     * Get token response data.
     *
     * @return string
     */
    public function getTokenResponse()
    {
        return $this->tokenResponse;
    }

    /**
     * Stores nonce.
     *
     * @param string $nonce
     *
     * @return string
     */
    protected function setNonce($nonce)
    {
        $_SESSION['openid_connect_nonce'] = $nonce;

        return $nonce;
    }

    /**
     * Get stored nonce.
     *
     * @return string
     */
    protected function getNonce()
    {
        return isset($_SESSION['openid_connect_nonce'])
            ? $_SESSION['openid_connect_nonce']
            : '';
    }

    /**
     * Cleanup nonce.
     *
     * @return void
     */
    protected function unsetNonce()
    {
        unset($_SESSION['openid_connect_nonce']);
    }

    /**
     * Store state.
     *
     * @param string $state
     *
     * @return string
     */
    protected function setState($state)
    {
        $_SESSION['openid_connect_state'] = $state;

        return $state;
    }

    /**
     * Get stored state.
     *
     * @return string
     */
    protected function getState()
    {
        return isset($_SESSION['openid_connect_state'])
            ? $_SESSION['openid_connect_state']
            : '';
    }

    /**
     * Cleanup state.
     *
     * @return void
     */
    protected function unsetState()
    {
        unset($_SESSION['openid_connect_state']);
    }

    /**
     * Perform a token introspection on provided token with the OIDC provider.
     *
     * OIDC introspection response has the following attributes as defined in
     * RFC7662.
     *
     *  Attribute        Type        Description
     *  active           boolean     REQUIRED.  Boolean indicator of whether or
     *                               not the presented token is currently active.
     *  scope            string      OPTIONAL.  A JSON string containing a
     *                               space-separated list of scopes associated
     *                               with this token.
     *  client_id        string      OPTIONAL. Client identifier for the client that
     *                               requested this token.
     *  username         string      OPTIONAL.  Human-readable identifier for the
     *                               resource owner who authorized this token.
     *  token_type       string      OPTIONAL.  Type of the token.
     *  exp              int         OPTIONAL.  Integer timestamp, measured in
     *                               the number of seconds since January 1 1970
     *                               UTC, indicating when this token will expire.
     *  iat              int         OPTIONAL.  Integer timestamp, measured in
     *                               the number of seconds since January 1 1970
     *                               UTC, indicating when this token was
     *                               originally issued.
     *  nbf              int         OPTIONAL.  Integer timestamp, measured in
     *                               the number of seconds since January 1 1970
     *                               UTC, indicating when this token is not to
     *                               be used before.
     *  sub              string      OPTIONAL.  Subject of the token.
     *  aud              string      OPTIONAL.  Service-specific string
     *                               identifier or list of string identifiers
     *                               representing the intended audience for this
     *                               token.
     *  iss              string      OPTIONAL.  String representing the issuer
     *                               of this token.
     *  jti              string      OPTIONAL.  String identifier for the token.
     *
     *
     * @param  string $token           Access token or refresh token to perform introspection on.
     * @param  string $token_type_hint Token type hint to provide to server defaulting to access_token.
     * @return IntrospectionResponse   Returns object for handling response.
     */
    public function introspectToken($token, $token_type_hint = 'access_token')
    {
      $introspection_endpoint = $this->getProviderConfigValue('introspection_endpoint');

      $token_params = [
        'token' => $token,
        'token_type_hint' => $token_type_hint
      ];

      // Consider Basic authentication if provider config is set this way
      $basic_auth_header_value = base64_encode($this->clientId . ':' . $this->clientSecret);
      $headers = ['Authorization: Basic ' . $basic_auth_header_value];

      // Convert token params to string format
      $token_params = http_build_query($token_params);

      return new IntrospectionResponse($this->fetchUrl($introspection_endpoint, $token_params, $headers));
    }
}
