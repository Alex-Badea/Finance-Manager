<?php

use Carbon\Carbon;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Filesystem\FileNotFoundException;

define('KEY_PATH', '/home/vagrant/code/_v_certs/httpCert.key');
define('CLIENT_ID', '41a5a3b0-0857-4cf9-a35b-132b6aa753e4');
define('SN', '5E4299BE');

function digest(string $data): string
{
    return 'SHA-256=' . base64_encode(openssl_digest($data, 'sha256', true));
}

/**
 * @param string $data
 * @return string
 * @throws FileNotFoundException
 * @throws EncryptException
 */
function sign(string $data): string
{
    $pk = openssl_get_privatekey('file://' . KEY_PATH);
    if (!$pk)
        throw new FileNotFoundException('Key not found ' . KEY_PATH);
    $signature = '';
    if (!openssl_sign($data, $signature, $pk, OPENSSL_ALGO_SHA256))
        throw new EncryptException('Signing failed');
    return base64_encode($signature);
}

/**
 * @param string $method
 * @param string $path
 * @param string $date
 * @param string $digest
 * @return string
 * @throws FileNotFoundException
 * @throws EncryptException
 */
function genSignature(string $method, string $path, string $date, string $digest): string
{
    $rawSignature = '(request-target): ' . $method . ' ' . $path
        . "\ndate: " . $date . "\ndigest: " . $digest;
    return sign($rawSignature);
}

/**
 * @param string $payload
 * @param string $method
 * @param string $path
 * @param bool $isClient
 * @return array
 * @throws FileNotFoundException
 */
function genStdHeaders(string $payload, string $method, string $path, bool $isClient = true): array
{
    $digest = digest($payload);
    $date = Carbon::now('UTC')->format('D, d M Y H:i:s \G\M\T');
    $id = $isClient ? CLIENT_ID : 'SN=' . SN;
    $signature = 'keyId="' . $id . '",algorithm="rsa-sha256",headers="(request-target) date digest",'
        . 'signature="' . genSignature($method, $path, $date, $digest) . '"';
    return ['Digest' => $digest, 'Date' => $date, 'Signature' => $signature];
}
