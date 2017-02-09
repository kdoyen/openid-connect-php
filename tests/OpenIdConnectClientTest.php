<?php
namespace OpenIdConnectClient\Tests;

use OpenIdConnectClient\OpenIdConnectClient;
use Prophecy\Prophecy\ObjectProphecy;

/**
 * Class OpenIdConnectClientTest
 *
 * @package OpenIdConnectClient\Tests
 */
class OpenIdConnectClientTest extends \PHPUnit_Framework_TestCase
{
    /**
     *
     */
    public function test_it_can_be_instantiated()
    {
        $client = new OpenIdConnectClient();

        $this->assertInstanceOf(OpenIdConnectClient::class, $client);
    }

    /**
     *
     */
    public function test_it_can_set_and_get_provider_url()
    {
        $client = new OpenIdConnectClient();

        $client->setProviderUrl('https://provider.local');

        $this->assertEquals($client->getProviderUrl(), 'https://provider.local');
    }

    /**
     *
     */
    public function test_it_can_add_and_get_response_types_data()
    {
        $client = new OpenIdConnectClient();

        $this->assertEmpty($client->getResponseTypes());

        $client->addResponseTypes(['foo', 'bar', 'baz']);

        $this->assertEquals(['foo', 'bar', 'baz'], $client->getResponseTypes());
    }

    /**
     *
     */
    public function test_it_can_add_and_get_scopes()
    {
        $client = new OpenIdConnectClient();

        $this->assertEmpty($client->getScopes());

        $client->addScopes(['foo', 'bar']);

        $this->assertEquals(['foo', 'bar'], $client->getScopes());
    }

    /**
     *
     */
    public function test_it_can_add_and_get_auth_params()
    {
        $client = new OpenIdConnectClient();

        $this->assertEmpty($client->getAuthParams());

        $client->addAuthParams(['hello' => 'world', 'foo' => 'bar']);

        $this->assertEquals(['hello' => 'world', 'foo' => 'bar'], $client->getAuthParams());
    }

    /**
     *
     */
    public function test_it_can_set_and_get_redirect_url()
    {
        $client = new OpenIdConnectClient();

        $client->setRedirectUrl('http://localhost:1234');

        $this->assertEquals('http://localhost:1234', $client->getRedirectUrl());
    }

    /**
     *
     */
    public function test_it_gets_current_url_if_no_redirect_url_is_set()
    {
        //FIXME am I testing this right?
        $_SERVER['HTTP_HOST'] = 'foobar.xyz';
        $_SERVER['SERVER_PORT'] = 443;
        $_SERVER['REQUEST_SCHEME'] = 'https';
        $_SERVER['REQUEST_URI'] = '/foo/bar';

        $client = new OpenIdConnectClient();

        $expected = 'https://foobar.xyz/foo/bar';

        $this->assertEquals($expected, $client->getRedirectUrl());
    }

    /**
     *
     */
    public function test_it_can_authenticate()
    {
        $this->markTestIncomplete('Refactor some things to separate classes, e.g. fetchUrl');
    }
}
