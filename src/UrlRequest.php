<?php

namespace OpenIdConnectClient;

class UrlRequest
{
    /**
     * HTTP proxy address, e.g. http://localhost:8080
     *
     * @var string
     */
    public $httpProxy;

    /**
     * Absolute path for SSL certificates.
     *
     * @var string
     */
    public $certPath;

    /**
     * Make a HTTP request.
     *
     * @param string $url URL address to make request against.
     * @param string $post_body Optional. If this contains anything the request type
     *                          will be POST.
     * @param mixed[] $headers Optional. Extra headers to be send with the request.
     *                         Format as 'NameHeader: ValueHeader'
     *
     * @return mixed
     */
    public function fetch($url, $post_body = '', array $headers = [])
    {
        if ($post_body === '') {
            return $this->get($url, $headers);
        }

        return $this->post($url, $post_body, $headers);
    }

    /**
     * Make a GET request.
     *
     * @throws OpenIdConnectException
     *
     * @param string $url
     * @param array $headers
     *
     * @return mixed
     */
    public function get($url, array $headers = [])
    {
        $headers = $this->parseHeaders($headers);

        $ch = $this->getCurlHandle($url);

        if (count($headers) > 0) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }

        $output = curl_exec($ch);

        if ($output === false) {
            throw new OpenIdConnectException('Curl error: ' . curl_error($ch));
        }

        curl_close($ch);

        return $output;
    }

    /**
     * Make a POST request.
     *
     * @throws OpenIdConnectException
     *
     * @param string $url
     * @param string $post_body
     * @param array $headers
     *
     * @return mixed
     */
    public function post($url, $post_body, array $headers = [])
    {
        $headers = $this->parseHeaders($headers);

        $ch = $this->getCurlHandle($url);

        // curl_setopt($ch, CURLOPT_POST, 1);
        // Allows to keep the POST method even after redirect
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post_body);

        if (!$this->headerExists('Content-type', $headers)) {
            // Default content type is form encoded
            $content_type = 'application/x-www-form-urlencoded';

            // Determine if this is a JSON payload and add the appropriate content type
            if (is_object(json_decode($post_body))) {
                $content_type = 'application/json';
            }

            $headers[] = 'Content-Type: ' . $content_type;
        }

        // Add POST-specific headers
        $headers[] = 'Content-Length: ' . strlen($post_body);

        // If we set some headers include them
        if (count($headers) > 0) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }

        $output = curl_exec($ch);

        if ($output === false) {
            throw new OpenIdConnectException('Curl error: ' . curl_error($ch));
        }

        curl_close($ch);

        return $output;
    }

    /**
     * Is a header set in a header collection?
     *
     * @access protected
     *
     * @param string $name
     * @param array $headers
     *
     * @return bool
     */
    protected function headerExists($name, array $headers = [])
    {
        if (empty($headers)) {
            return false;
        }

        $has = false;

        foreach ($headers as $header) {
            if (strpos($header, $name . ':') === 0) {
                $has = true;

                break;
            }
        }

        return $has;
    }

    /**
     * Parse headers for cURL ready format.
     *
     * @access protected
     *
     * @param array $headers
     *
     * @return array
     */
    protected function parseHeaders(array $headers)
    {
        if (empty($headers)) {
            return $headers;
        }

        $parsedHeaders = [];

        // Format all headers as `Key: Value`.
        foreach ($headers as $key => $value) {
            if (!is_numeric($key)) {
                $parsedHeaders[] = sprintf('%s: %s', $key, $value);
            } else {
                $parsedHeaders[] = $value;
            }
        }

        return $parsedHeaders;
    }

    /**
     * Get a generic cURL handle for request usage.
     *
     * @access protected
     *
     * @param string $url
     *
     * @return bool|\resource
     */
    protected function getCurlHandle($url)
    {
        // OK cool - then let's create a new cURL resource handle
        $ch = curl_init();

        // Set URL to download
        curl_setopt($ch, CURLOPT_URL, $url);

        // Include header in result? (0 = yes, 1 = no)
        curl_setopt($ch, CURLOPT_HEADER, 0);

        // Allows to follow redirect
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

        // Should cURL return or print out the data? (true = return, false = print)
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        // Timeout in seconds
        curl_setopt($ch, CURLOPT_TIMEOUT, 60);

        if (!empty($this->httpProxy)) {
            curl_setopt($ch, CURLOPT_PROXY, $this->httpProxy);
        }

        /**
         * Set cert path if certPath has been provided
         *
         * Removed setting CURLOPT_SSL_VERIFYPEER to false if certPath is empty
         * to force Curl to fall back to the default of true.
         *
         * This default value can be changed by setting libcurl environment
         * variables on broken implementations.
         */
        if (!empty($this->certPath)) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
            curl_setopt($ch, CURLOPT_CAINFO, $this->certPath);
        }

        if (curl_errno($ch)) {
            throw new OpenIdConnectException(curl_error($ch));
        }

        return $ch;
    }
}
