<?php

use Carbon\Carbon;
use GuzzleHttp\Exception\ClientException;
use Illuminate\Support\Facades\Route;
use GuzzleHttp\Client;

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

Route::get('/', function () {
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
            'authorization' => 'Signature keyId="' . keyId . '",algorithm="rsa-sha256",'
                . 'headers="(request-target) date digest",signature="' . $signature . '"',
        ],
        'form_params' => ['grant_type' => 'client_credentials'],
        'cert' => '/home/vagrant/code/_v_certs/example_client_tls.cer',
        'ssl_key' => '/home/vagrant/code/_v_certs/example_client_tls.key'
    ]);
    dd($response->getBody()->getContents());
});
