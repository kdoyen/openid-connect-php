<?php

namespace OpenIdConnectClient\Tests;

use OpenIdConnectClient\IntrospectionResponse;

/**
 * Class IntrospectionResponseTest.
 */
class IntrospectionResponseTest extends \PHPUnit_Framework_TestCase
{
    /**
     *
     */
    public function test_it_can_be_instantiated()
    {
        $object = new IntrospectionResponse();

        $this->assertInstanceOf(IntrospectionResponse::class, $object);
    }

    /**
     *
     */
    public function test_loading_data_in_constructor()
    {
        $data = (object) [
        'active' => true
        ];

        $object = new IntrospectionResponse($data);
        $this->assertTrue($object->isActive());

        $object = new IntrospectionResponse(json_encode($data));
        $this->assertTrue($object->isActive());
    }

    /**
     *
     */
    public function test_invalid_expired_data()
    {
        $data = (object) [
        'active' => true,
        'exp' => time() - 3600
        ];

        $object = new IntrospectionResponse(json_encode($data));
        $this->assertTrue($object->isExpired());
        $this->assertFalse($object->isValid());
        $this->assertFalse($object->isActive());
    }

    /**
     *
     */
    public function test_invalid_before_use()
    {
        $data = (object) [
        'active' => true,
        'exp' => time() + 3600,
        'nbf' => time() + 1800
        ];

        $object = new IntrospectionResponse(json_encode($data));
        $this->assertFalse($object->isValid());
        $this->assertFalse($object->isActive());

        $data->nbf = time() - 3600;

        $object = new IntrospectionResponse(json_encode($data));
        $this->assertFalse($object->isExpired());
        $this->assertTrue($object->isValid());
        $this->assertTrue($object->isActive());
    }

    /**
     *
     */
    public function test_getting_and_checking_scopes()
    {
        $scopes = ['openid', 'profile', 'offline_access'];
        $invalidScopes = ['email', '', '!#%!#', 1234, false, true];
        $data = (object) [
        'active' => true,
        'exp' => time() + 3600,
        'nbf' => time() - 3600,
        'scope' => implode(' ', $scopes)
        ];

        $object = new IntrospectionResponse(json_encode($data));
        foreach ($scopes as $scope) {
            $this->assertTrue($object->hasScope($scope));
        }

        foreach ($invalidScopes as $scope) {
            $this->assertFalse($object->hasScope($scope));
        }
    }

    /**
     *
     */
    public function test_empty_scopes()
    {
        $scopes = ['openid', 'profile', 'offline_access'];
        $data = (object) [
        'active' => true,
        'exp' => time() + 3600,
        'nbf' => time() - 3600
        ];

        $object = new IntrospectionResponse(json_encode($data));
        foreach ($scopes as $scope) {
            $this->assertFalse($object->hasScope($scope));
        }

        $object = new IntrospectionResponse();
        foreach ($scopes as $scope) {
            $this->assertFalse($object->hasScope($scope));
        }
    }

    /**
     *
     */
    public function test_magic_call_access()
    {
        $data = (object) [
        'active' => true,
        'exp' => time() + 3600,
        'nbf' => time() - 3600
        ];

        $notSetItems = ['iss', 'scope', 'client_id'];

        $object = new IntrospectionResponse(json_encode($data));

        foreach ($data as $key => $value) {
            $this->assertEquals($object->$key, $value);
        }

        foreach ($notSetItems as $key) {
            $this->assertNull($object->$key);
        }
    }

    /**
     * @expectedException OpenIdConnectClient\OpenIdConnectException
     * @expectedExceptionMessage Invalid introspection response
     */
    public function test_invalid_data_provided()
    {
        $object = new IntrospectionResponse(12345);
    }

    /**
     *
     */
    public function test_to_string_json_output()
    {
      $data = (object) [
      'active' => true,
      'exp' => time() + 3600,
      'nbf' => time() - 3600,
      ];

      $object = new IntrospectionResponse(json_encode($data));
      $this->assertJsonStringEqualsJsonString(json_encode($data), (string) $object);
    }

    /**
     *
     */
    public function test_missing_active_in_response()
    {
        $data = (object) [
        ];

        $object = new IntrospectionResponse(json_encode($data));
        $this->assertFalse($object->isActive());
    }
}
