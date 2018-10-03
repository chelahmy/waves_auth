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
require_once('dictionary.php');

class waves_auth {

	protected function pack_msg($host, $data) {
		return array_merge(
			str2byteswl('WavesWalletAuthentication'),
			str2byteswl($host),
			str2byteswl($data)
			);
	}
	
	// Sign the data.
	// prik: private key
	// host: the domain name part of the referrer host url
	// data: the data to be signed
	public function sign($prik, $host, $data) {
		$m = $this->pack_msg($host, $data);

		$b58 = new base58;
		$p = $b58->decode($prik);

		$a = new axlsign;
		$opt_random = $this->generate_random_array(64);
		return $b58->encode($a->sign($p, $m, $opt_random));
	}
	
	// Verify signature to the data.
	// pubk: public key
	// sig: signature
	// host: the domain name part of the referrer host url
	// data: the data submited by the referrer
	public function verify($pubk, $sig, $host, $data) {
		$m = $this->pack_msg($host, $data);

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

	protected function build_seed_hash($seedBytes) {
		$nonce = array_fill(0, 4, 0); // INITIAL_NONCE = 0
		$seedBytesWithNonce = array_merge($nonce, $seedBytes);
		$seedHash = $this->hash_chain($seedBytesWithNonce);
		$shstr = implode('', array_map(function($v){return chr($v);}, $seedHash));
		return hex2bytes(hash("sha256", $shstr));
	}

	// Build the private & public key pair from the seed string.
	public function build_key_pair($seed) {

		if (!is_string($seed)) {
			throw new Exception('Missing or invalid seed phrase');
		}

		$seedBytes = str2bytes($seed);
		$seedHash = $this->build_seed_hash($seedBytes);
		$a = new axlsign;
		$keys = $a->generateKeyPair($seedHash);
		$b58 = new base58;
		
		return array(
			'privateKey' => $b58->encode($keys['private']),
			'publicKey' => $b58->encode($keys['public'])
		);
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
	public function get_address($publicKey) {
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
	
	// Generate secure random array
	public function generate_random_array($length) {

		if ($length <= 0) {
			throw new Exception('Missing or invalid array length');
		}

		$a = openssl_random_pseudo_bytes($length);
		$b = openssl_random_pseudo_bytes($length);
		$result = array_fill(0, $length, 0);

		for ($i = 0; $i < $length; $i++) {
			$hash = hash("sha256", $a[$i] . $b[$i]);
			$result[$i] = intval(substr($hash, 0, 12), 16);
		}

		return $result;
	}

	// Generate new seed
	public function generate_new_seed($length) {
		global $seed_dictionary;
		
		$random = $this->generate_random_array($length);
		$wordCount = count($seed_dictionary);
		$phrase = array(0, $length, 0);
		
		for ($i = 0; $i < $length; $i++) {
			$wordIndex = $random[$i] % $wordCount;
			$phrase[$i] = $seed_dictionary[$wordIndex];
		}
		
		return implode(' ', $phrase);
	}
	
}
