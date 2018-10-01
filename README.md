# waves_auth
[Waves Auth API](https://docs.wavesplatform.com/en/development-and-api/client-api/auth-api.html) Verification Handler and Key-pair Generation from Seed

This module handles the response from the Wave Auth API's call. The Waves Auth API is simply REST. However, the response verification requires **curve25519**, **blake2b** and **keccak** hashing algorithms which Waves implemented in Typescript and few other languages but not PHP. This PHP module was manually converted from the 32-bit based Typescript implementations.

Verification steps:
1. The response from the API's call contain a *signature* that needs to be verified using the returned *public key*. Use **waves_auth::verify()**.
2. The *public key* needs to be verified that it belongs to the returned *address*. Use **waves_auth::get_address()**.
3. The *address* itself needs to be checked for validity. Use **waves_auth::is_valid_address()**.
4. The *address* may need to be verified that it exists in the blockchain. (Not part of this module. Please refer to the Waves API)

## Verification Example
~~~php
require_once('waves_auth.php');

$host = 'demo.wavesplatform.com';
$data = 'Please visit blindtalk.net and jualla.com';
$sig = '2XbDzTvKJp4LxNzGJDwvF7rtYRcL8G5pphj9M64sHCNekt5HwYaXmE7PRJFWfavzRU5wdVYEwtJNyeLTnrWFTHoL';
$puk = 'CbDnhryczrZRpxDxmvwZndVukYkGV9H17hLXGRKJ8fyx';
$addr = '3P9pSqybo9S7tBu83KNG8HK72TZ6dR4DkZ8';

$wa = new waves_auth;

if ($wa->verify($puk, $sig, $host, $data))
  echo "OK: The signature is valid<br/>";
else
  echo "Not OK: The signature is NOT valid<br/>";

if ($wa->is_valid_address($addr))
  echo "OK: The address is valid<br/>";
else
  echo "Not OK: The address is NOT valid<br/>";

if ($wa->get_address($puk) === $addr)
  echo "OK: The public key and the address are matched<br/>";
else
  echo "Not OK: The public key and the address are NOT matched<br/>";
~~~

## Key-pair Generation Example
~~~php
$seed = 'bachelor garden grit error awake depend nice result worth when ugly point uphold zoo seven';
echo "seed: ($seed)<br>";

$wa = new waves_auth;

$kp = $wa->build_key_pair($seed);

echo "private key: ". $kp['privateKey'] . "<br/>";
echo "public key: ". $kp['publicKey'] . "<br/>";

$ad = $wa->get_address($kp['publicKey']);

echo 'address: ' .  $ad . '<br/><br/>';
~~~
