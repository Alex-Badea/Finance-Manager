<?php

use Carbon\Carbon;
use GuzzleHttp\Exception\ClientException;
use Illuminate\Support\Facades\Route;
use GuzzleHttp\Client;
use Illuminate\Support\Facades\Session;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/ob', function () {
    define('keyId', 'e77d776b-90af-4684-bebc-521e5b2614dd');
    define('method', 'POST');
    define('baseUrl', 'https://api.sandbox.ing.com');
    define('path', '/oauth2/token');
    define('payload', 'grant_type=client_credentials');
    define('digest', 'SHA-256=' . base64_encode(
            openssl_digest(payload, 'sha256', true)));
    define('date', Carbon::now('UTC')->format('D, d M Y H:i:s \G\M\T'));
    define('rawSignature', '(request-target): ' . strtolower(method)
        . ' ' . path . "\ndate: " . date . "\ndigest: " . digest);

    $pk = openssl_get_privatekey(
        'file:///home/vagrant/code/_v_certs/example_client_signing.key', 'changeit');
    if (!$pk)
        dd('pk fail');

    $signature = '';
    openssl_sign(rawSignature, $signature, $pk, OPENSSL_ALGO_SHA256);
    $signature = base64_encode($signature);

    $client = new Client();
    $response = $client->post(baseUrl . path, [
        'headers' => [
            'Digest' => digest,
            'Date' => date,
            'Authorization' => 'Signature keyId="' . keyId . '",algorithm="rsa-sha256",'
                . 'headers="(request-target) date digest",signature="' . $signature . '"',
        ],
        'form_params' => ['grant_type' => 'client_credentials'],
        'cert' => '/home/vagrant/code/_v_certs/example_client_tls.cer',
        'ssl_key' => '/home/vagrant/code/_v_certs/example_client_tls.key'
    ]);
    $token = json_decode($response->getBody())->access_token;
    dd($token);
});

Route::get('/psd2', function () {
    define('keyId', 'SN=5E4299BE');
    define('method', 'POST');
    define('baseUrl', 'https://api.sandbox.ing.com');
    define('path', '/oauth2/token');
    define('payload', 'grant_type=client_credentials');
    define('digest', 'SHA-256=' . base64_encode(
            openssl_digest(payload, 'sha256', true)));
    define('date', Carbon::now('UTC')->format('D, d M Y H:i:s \G\M\T'));
    define('rawSignature', '(request-target): ' . strtolower(method)
        . ' ' . path . "\ndate: " . date . "\ndigest: " . digest);

    $pk = openssl_get_privatekey(
        'file:///home/vagrant/code/_v_certs/example_eidas_client_signing.key', 'changeit');
    if (!$pk)
        dd('pk fail');

    $signature = '';
    openssl_sign(rawSignature, $signature, $pk, OPENSSL_ALGO_SHA256);
    $signature = base64_encode($signature);

    $client = new Client();
    $response = $client->post(baseUrl . path, [
        'headers' => [
            'Digest' => digest,
            'Date' => date,
            'Authorization' => 'Signature keyId="' . keyId . '",algorithm="rsa-sha256",'
                . 'headers="(request-target) date digest",signature="' . $signature . '"',
            'TPP-Signature-Certificate' => '-----BEGIN CERTIFICATE-----MIIENjCCAx6gAwIBAgIEXkKZvjANBgkqhkiG9w0BAQsFADByMR8wHQYDVQQDDBZBcHBDZXJ0aWZpY2F0ZU1lYW5zQVBJMQwwCgYDVQQLDANJTkcxDDAKBgNVBAoMA0lORzESMBAGA1UEBwwJQW1zdGVyZGFtMRIwEAYDVQQIDAlBbXN0ZXJkYW0xCzAJBgNVBAYTAk5MMB4XDTIwMDIxMDEyMTAzOFoXDTIzMDIxMTEyMTAzOFowPjEdMBsGA1UECwwUc2FuZGJveF9laWRhc19xc2VhbGMxHTAbBgNVBGEMFFBTRE5MLVNCWC0xMjM0NTEyMzQ1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkJltvbEo4/SFcvtGiRCar7Ah/aP0pY0bsAaCFwdgPikzFj+ij3TYgZLykz40EHODtG5Fz0iZD3fjBRRM/gsFPlUPSntgUEPiBG2VUMKbR6P/KQOzmNKF7zcOly0JVOyWcTTAi0VAl3MEO/nlSfrKVSROzdT4Aw/h2RVy5qlw66jmCTcp5H5kMiz6BGpG+K0dxqBTJP1WTYJhcEj6g0r0SYMnjKxBnztuhX5XylqoVdUy1a1ouMXU8IjWPDjEaM1TcPXczJFhakkAneoAyN6ztrII2xQ5mqmEQXV4BY/iQLT2grLYOvF2hlMg0kdtK3LXoPlbaAUmXCoO8VCfyWZvqwIDAQABo4IBBjCCAQIwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cHM6Ly93d3cuaW5nLm5sL3Rlc3QvZWlkYXMvdGVzdC5jcmwwHwYDVR0jBBgwFoAUcEi7XgDA9Cb4xHTReNLETt+0clkwHQYDVR0OBBYEFLQI1Hig4yPUm6xIygThkbr60X8wMIGGBggrBgEFBQcBAwR6MHgwCgYGBACORgEBDAAwEwYGBACORgEGMAkGBwQAjkYBBgIwVQYGBACBmCcCMEswOTARBgcEAIGYJwEDDAZQU1BfQUkwEQYHBACBmCcBAQwGUFNQX0FTMBEGBwQAgZgnAQIMBlBTUF9QSQwGWC1XSU5HDAZOTC1YV0cwDQYJKoZIhvcNAQELBQADggEBAEW0Rq1KsLZooH27QfYQYy2MRpttoubtWFIyUV0Fc+RdIjtRyuS6Zx9j8kbEyEhXDi1CEVVeEfwDtwcw5Y3w6Prm9HULLh4yzgIKMcAsDB0ooNrmDwdsYcU/Oju23ym+6rWRcPkZE1on6QSkq8avBfrcxSBKrEbmodnJqUWeUv+oAKKG3W47U5hpcLSYKXVfBK1J2fnk1jxdE3mWeezoaTkGMQpBBARN0zMQGOTNPHKSsTYbLRCCGxcbf5oy8nHTfJpW4WO6rK8qcFTDOWzsW0sRxYviZFAJd8rRUCnxkZKQHIxeJXNQrrNrJrekLH3FbAm/LkyWk4Mw1w0TnQLAq+s=-----END CERTIFICATE-----',
        ],
        'form_params' => ['grant_type' => 'client_credentials'],
        'cert' => '/home/vagrant/code/_v_certs/example_eidas_client_tls.cer',
        'ssl_key' => '/home/vagrant/code/_v_certs/example_eidas_client_tls.key'
    ]);
    $token = json_decode($response->getBody())->access_token;
    file_put_contents('token.txt', $token);
    $id = json_decode($response->getBody())->client_id;
    file_put_contents('id.txt', $id);

    // Client auth
    $method = 'GET';
    $redirectUrl = 'http://financial-manager.test/success';
    $scope = 'payment-accounts%3Abalances%3Aview%20payment-accounts%3Atransactions%3Aview';
    $path = '/oauth2/authorization-server-url?scope=' . $scope
        . '&redirect_uri=' . $redirectUrl . '&country_code=RO';
    $digest = 'SHA-256=' . base64_encode(openssl_digest('', 'sha256'));
    $rawSignature = '(request-target): ' . strtolower($method) . ' ' . $path
        . "\ndate: " . date . "\ndigest: " . $digest;

    $signature = '';
    openssl_sign($rawSignature, $signature, $pk, OPENSSL_ALGO_SHA256);
    $signature = base64_encode($signature);

    $response = $client->get(baseUrl . $path, [
        'headers' => [
            'Digest' => $digest,
            'Date' => date,
            'Authorization' => 'Bearer ' . $token,
            'Signature' => 'keyId="' . $id . '",algorithm="rsa-sha256",'
                . 'headers="(request-target) date digest",signature="' . $signature . '"'
        ],
        'form_params' => ['grant_type' => 'client_credentials'],
        'cert' => '/home/vagrant/code/_v_certs/example_eidas_client_tls.cer',
        'ssl_key' => '/home/vagrant/code/_v_certs/example_eidas_client_tls.key'
    ]);

    $location = json_decode($response->getBody())->location;
    $location .= '?client_id=' . $id . '&scope=' . $scope . '&redirect_uri=' . $redirectUrl;
    dd($location);
});

Route::get('/success', function () {
    define('keyId', file_get_contents('id.txt'));
    define('auth', request('code'));
    define('token', file_get_contents('token.txt'));
    define('baseUrl', 'https://api.sandbox.ing.com');
    define('method', 'POST');
    define('path', '/oauth2/token');
    define('payload', 'grant_type=authorization_code&code=' . auth);
    define('digest', 'SHA-256=' . base64_encode(
            openssl_digest(payload, 'sha256', true)));
    define('date', Carbon::now('UTC')->format('D, d M Y H:i:s \G\M\T'));
    define('rawSignature', '(request-target): ' . strtolower(method)
        . ' ' . path . "\ndate: " . date . "\ndigest: " . digest);

    $pk = openssl_get_privatekey(
        'file:///home/vagrant/code/_v_certs/example_eidas_client_signing.key', 'changeit');
    if (!$pk)
        dd('pk fail');

    $signature = '';
    openssl_sign(rawSignature, $signature, $pk, OPENSSL_ALGO_SHA256);
    $signature = base64_encode($signature);

    $client = new Client();
    $response = $client->post(baseUrl . path, [
        'headers' => [
            'Digest' => digest,
            'Date' => date,
            'Authorization' => 'Bearer ' . token,
            'Signature' => 'keyId="' . keyId . '",algorithm="rsa-sha256",'
                . 'headers="(request-target) date digest",signature="' . $signature . '"',
        ],
        'form_params' => [
            'grant_type' => 'authorization_code',
            'code' => auth
        ],
        'cert' => '/home/vagrant/code/_v_certs/example_client_tls.cer',
        'ssl_key' => '/home/vagrant/code/_v_certs/example_client_tls.key'
    ]);
    $token = json_decode($response->getBody())->access_token;

    // Account information service - accounts
    $method = 'GET';
    $path = '/v3/accounts';
    $digest = 'SHA-256=' . base64_encode(openssl_digest('', 'sha256'));
    $rawSignature = '(request-target): ' . strtolower($method)
        . ' ' . $path . "\ndate: " . date . "\ndigest: " . $digest;
    openssl_sign($rawSignature, $signature, $pk, OPENSSL_ALGO_SHA256);
    $signature = base64_encode($signature);
    $response = $client->get(baseUrl . $path, [
        'headers' => [
            'Digest' => $digest,
            'Date' => date,
            'Authorization' => 'Bearer ' . $token,
            'Signature' => 'keyId="' . keyId . '",algorithm="rsa-sha256",'
                . 'headers="(request-target) date digest",signature="' . $signature . '"',
        ],
        'cert' => '/home/vagrant/code/_v_certs/example_client_tls.cer',
        'ssl_key' => '/home/vagrant/code/_v_certs/example_client_tls.key'
    ]);
    dump(json_decode($response->getBody()));

    // Account information service - balance
    $path = json_decode($response->getBody())->accounts[0]->_links->balances->href;
    $rawSignature = '(request-target): ' . strtolower($method)
        . ' ' . $path . "\ndate: " . date . "\ndigest: " . $digest;
    openssl_sign($rawSignature, $signature, $pk, OPENSSL_ALGO_SHA256);
    $signature = base64_encode($signature);
    dump($path);

    /*$response = $client->get(baseUrl . $path, [
        'headers' => [
            'Digest' => $digest,
            'Date' => date,
            'Authorization' => 'Bearer ' . $token,
            'Signature' => 'keyId="' . keyId . '",algorithm="rsa-sha256",'
                . 'headers="(request-target) date digest",signature="' . $signature . '"',
        ],
        'cert' => '/home/vagrant/code/_v_certs/example_client_tls.cer',
        'ssl_key' => '/home/vagrant/code/_v_certs/example_client_tls.key'
    ]);
    dump(json_decode($response->getBody()));*/
});
