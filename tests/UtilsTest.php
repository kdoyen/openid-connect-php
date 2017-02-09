<?php

namespace OpenIdConnectClient\Tests;

use OpenIdConnectClient\Utils;

/**
 * Class UtilsTest.
 */
class UtilsTest extends \PHPUnit_Framework_TestCase
{
    public function test_base64url_decode()
    {
      // Both strings were encoded with the same text data that creates a base64
      // encoding that is invalid within a url.
      $decodedSample1 = Utils::base64url_decode('IuOBk-OCk-OBq-OBoeOBryI');
      $decodedSample2 = base64_decode('IuOBk+OCk+OBq+OBoeOBryI=');
      $this->assertEquals($decodedSample1, $decodedSample2);
    }
}
