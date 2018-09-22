<?php
// base58.php
// Waves base58 encoder
// Converted from base58.ts 
// By Abdullah Daud, chelahmy@gmail.com
// 19 September 2018

class base58 {

	private $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
	 
	function encode($buffer) {
		$len = count($buffer);
		
		if ($len <= 0) return '';

		$digits = array(0);

		for ($i = 0; $i < $len; $i++) {

			for ($j = 0; $j < count($digits); $j++) {
				$digits[$j] <<= 8;
			}

			$digits[0] += $buffer[$i];
			$carry = 0;

			for ($k = 0; $k < count($digits); $k++) {
				$digits[$k] += $carry;
				$carry = ($digits[$k] / 58) | 0;
				$digits[$k] %= 58;
			}

			while ($carry) {
				array_push($digits, $carry % 58);
				$carry = ($carry / 58) | 0;
			}

		}

		for ($i = 0; $buffer[$i] === 0 && $i < $len - 1; $i++) {
			array_push($digits, 0);
		}

		$digits = array_reverse($digits);
		$len = count($digits);
		$alphas = array();
		
		for ($i = 0; $i < $len; $i++)
			$alphas[] = $this->alphabet[$digits[$i]];

		return implode('', $alphas);			
	}

	function decode($str) {
		$alphabet_map = str_split($this->alphabet);

		$len = strlen($str);
		if ($len <= 0) return array();

		$bytes = [0];

		for ($i = 0; $i < $len; $i++) {

			$c = $str[$i];
			if (!in_array($c, $alphabet_map)) {
				throw new Exception('There is no character "'. $c .'" in the Base58 sequence!');
			}

			for ($j = 0; $j < count($bytes); $j++) {
				$bytes[$j] *= 58;
			}

			$bytes[0] += array_search($c, $alphabet_map);
			$carry = 0;

			for ($j = 0; $j < count($bytes); $j++) {
				$bytes[$j] += $carry;
				$carry = $bytes[$j] >> 8;
				$bytes[$j] &= 0xff;
			}

			while ($carry) {
				array_push($bytes, $carry & 0xff);
				$carry >>= 8;
			}
		}

		for ($i = 0; $str[$i] === '1' && $i < $len - 1; $i++) {
			array_push($bytes, 0);
		}

		return array_reverse($bytes);	
	}
}

