<?php

namespace OpenIdConnectClient;

/**
 * Class IntrospectionResponse.
 *
 * Provides class for interacting with an OIDC introspection response as expected per rfc 7662
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
 */
class IntrospectionResponse
{
    /**
   * Client ID used for interacting with OpenID provider.
   *
   * @var object
   */
  protected $response;

  /**
   * IntrospectionResponse constructor.
   *
   * @param mixed $introspectionResponse Provide either the JSON string or an object as the response to use.
   */
  public function __construct($introspectionResponse = null)
  {
      if (!empty($introspectionResponse)) {
          $this->setResponse($introspectionResponse);
      }
  }

  /**
   * Sets the internal response object from a provided introspection response.
   *
   * @param string|object $introspectionResponse Provide either the JSON string or an object as the response to use.
   *
   * @throws OpenIdConnectException
   *
   * @return true
   */
  public function setResponse($introspectionResponse)
  {
      if (is_object($introspectionResponse)) {
          $this->response = $introspectionResponse;
      } elseif (is_string($introspectionResponse) &&
      ($decodedJson = json_decode($introspectionResponse)) &&
      is_object($decodedJson)) {
          $this->response = $decodedJson;
      } else {
          throw new OpenIdConnectException('Invalid introspection response');
      }

      return true;
  }

  /**
   * Gets the internal introspection response object.
   *
   * @return object|bool returns an object or false if not available
   */
  public function getResponse()
  {
      if (!empty($this->response) && is_object($this->response)) {
          return $this->response;
      }

      return false;
  }

  /**
   * Converts the internal response object to a json encoded string.
   *
   * @return string|bool returns json_encode version of internal object or false on error.
   */
  public function __toString()
  {
      return json_encode($this->response);
  }

  /**
   * Determines if token response claims token is active.
   *
   * @return bool true if token is still active and is valid, false otherwise.
   */
  public function isActive()
  {
      if ($response = $this->getResponse()) {
          if (!empty($response->active) && $response->active === true && $this->isValid()) {
              return true;
          }
      }

      return false;
  }

  /**
   * Determines if token provided is expired.
   *
   * @return bool Returns true if an expiration value is set and has elapsed, false otherwise.
   */
  public function isExpired()
  {
      if ($response = $this->getResponse()) {
          if (!empty($response->exp)) {
              return time() >= $response->exp;
          }
      }

      return false;
  }

  /**
   * Checks wither the response provided is valid in that it is not expired and, if provided, isn't being used earlier than intended.
   *
   * @return bool true if response is
   */
  public function isValid()
  {
      if (!$this->isExpired() && ($response = $this->getResponse())) {
          // check if nbf (Not before) is provided and in the past
        if (!empty($response->nbf)) {
            return time() >= $response->nbf;
        }

        // is valid because not expired and nbf was not provided
        return true;
      }

      return false;
  }
  /**
   * Gets the scopes from the response and turns them into an array.
   *
   * @return array Array containing available scopes provided.
   */
  public function getScopes()
  {
      if ($response = $this->getResponse()) {
          return (!empty($response->scope) &&
        is_string($response->scope)) ?
        explode(' ', strtolower($response->scope)) : [];
      }

      return [];
  }

  /**
   * Checks wither or not a scope provided is included in the response.
   *
   * @param  string  $scope Name of scope to check
   *
   * @return bool        returns true if scope exists in response false otherwise.
   */
  public function hasScope($scope)
  {
      if ($scopes = $this->getScopes()) {
          return in_array(strtolower($scope), $scopes);
      }

      return false;
  }

  /**
   * Magic __get() method to allow direct read-only object access to response
   * object. For use to access properties that don't have a direct getter.
   *
   * @param  string $name Name of property being requested that doesn't exist.
   *
   * @return [type]       [description]
   */
  public function __get($name)
  {
      if ($response = $this->getResponse()) {
        if (!empty($response->$name)) {
          return $response->$name;
        }
      }
  }
}
