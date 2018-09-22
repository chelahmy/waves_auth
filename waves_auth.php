<?php
// waves_auth.php
// Wave authentication verification handler
// By Abdullah Daud, chelahmy@gmail.com
// 22 September 2018

/**
 * Please refer to Waves Auth API - https://docs.wavesplatform.com/en/development-and-api/client-api/auth-api.html
 *
 * This module handles the response from the Wave Auth API call on the main net.
 *
 * Verification:
 * 1. The response from the API call contain a signature that
 *    needs to be verified using the returned public key.
 *    Use waves_auth::verify().
 * 2. The public key needs to be verified that it belongs to the
 *    returned address. Use waves_auth::get_address().
 * 3. The address itself needs to be checked for validity.
 *    Use waves_auth::is_valid_address().
 * 4. The address may need to be verified that it exists in the
 *    blockchain.
 *
 */

require_once('axlsign.php');
require_once('blake2b.php');
require_once('keccak.php');
require_once('base58.php');
require_once('utils32.php');

class waves_auth {

	// Verify signature to the data.
	// pubk: public key
	// sig: signature
	// host: the domain name part of the referrer host url
	// data: the data submited by the referrer
	public function verify($pubk, $sig, $host, $data) {
		$m = array_merge(
			str2byteswl('WavesWalletAuthentication'),
			str2byteswl($host),
			str2byteswl($data)
			);

		$b58 = new base58;

		$p = $b58->decode($pubk);
		$s = $b58->decode($sig);

		$a = new axlsign;
	
		return $a->verify($p, $m, $s);
	}

	protected function hash_chain($input) {
		$b = new blake2b();
		$bout = $b->blake2b($input, null, 32);
		$k = new keccak();
		return $k->digest($bout);
	}

	// Check the validity of the Waves address.
	public function is_valid_address($address) {

		if (!is_string($address)) {
			throw new Exception('Missing or invalid address');
		}

		$b58 = new base58;
		$addressBytes = $b58->decode($address);

		if (!is_array($addressBytes))
			return false;
		
		$len = count($addressBytes);
		
		if ($len < 26 || $addressBytes[0] !== 1 || $addressBytes[1] !== ord('W')) {
			return false;
		}

		$key = array_slice($addressBytes, 0, 22);
		$check = array_slice($addressBytes, 22, 4);
		$hash = $this->hash_chain($key);
		$keyHash = array_slice($hash, 0, 4);

		for ($i = 0; $i < 4; $i++) {
			if ($check[$i] !== $keyHash[$i]) {
				return false;
			}
		}

		return true;
	}

	// Generate Waves address from the public key.
	function get_address($publicKey) {
		$b58 = new base58;
		$publicKeyBytes = $b58->decode($publicKey);

		if (!is_array($publicKeyBytes) || count($publicKeyBytes) !== 32) {
			throw new Exception("Missing or invalid public key");
		}
	
		$prefix = [1, ord('W')];
		$publicKeyHashPart = array_slice($this->hash_chain($publicKeyBytes), 0, 20);
		$rawAddress = array_merge($prefix, $publicKeyHashPart);
		$addressHash = array_slice($this->hash_chain($rawAddress),0, 4);
	
		return $b58->encode(array_merge($rawAddress, $addressHash));
	}
}
