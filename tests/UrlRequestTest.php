<?php

namespace OpenIdConnectClient\Tests;

use OpenIdConnectClient\UrlRequest;

/**
 * Class UrlRequestTest
 *
 * @package OpenIdConnectClient\Tests
 */
class UrlRequestTest extends \PHPUnit_Framework_TestCase
{
    /**
     *
     */
    public function test_it_can_be_instantiated()
    {
        $req = new UrlRequest();

        $this->assertInstanceOf(UrlRequest::class, $req);
    }

    /**
     *
     */
    public function test_it_makes_get_requests()
    {
        $req = new UrlRequest();

        $result = $req->get('http://example.com');
        $this->assertRegExp('%Example Domain%', $result);
    }

    /**
     *
     */
    public function test_it_makes_https_get_requests()
    {
        $req = new UrlRequest();

        $result = $req->get('https://example.com');
        $this->assertRegExp('%Example Domain%', $result);
    }

    /**
     *
     */
    public function test_it_makes_post_request()
    {
        $req = new UrlRequest();

        $result = $req->post('http://example.com', '{}');

        $this->assertRegExp('%Example Domain%', $result);
    }

    /**
     *
     */
    public function test_it_selects_get_or_post_with_fetch()
    {
        $req = new UrlRequest();

        $get = $req->fetch('http://example.com');
        $post = $req->fetch('http://example.com', '{}');

        $this->assertRegExp('%Example Domain%', $get);
        $this->assertRegExp('%Example Domain%', $post);
    }
}
