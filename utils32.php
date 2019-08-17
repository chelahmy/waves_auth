<?php
// utils32.php
// Utility functions for bytes and 32-bits handling. 
// By Abdullah Daud, chelahmy@gmail.com
// 22 September 2018

function str2bytes($str) {
	$str_arr = str_split($str);
	$len = count($str_arr);
	
	if ($len <= 0)
		return array(0, 0);
	
	$bytes = array_fill(0, $len, 0);
	
	for ($i = 0; $i < $len; $i++)
		$bytes[$i] = ord($str_arr[$i]);
	
	return $bytes;
}

function str2byteswl($str) {
	$str_arr = str_split($str);
	$len = count($str_arr);
	
	if ($len <= 0)
		return array(0, 0);
	
	$bytes = array_fill(0, $len + 2, 0);
	
	// big-endian
	$bytes[0] = intval($len / 256);
	$bytes[1] = intval($len % 256);
	
	for ($i = 0; $i < $len; $i++)
		$bytes[$i+2] = ord($str_arr[$i]);
	
	return $bytes;
}

function hex2bytes($hexstr) {
	if (!is_string($hexstr) || !ctype_xdigit($hexstr))
		return array();
		
	$len = strlen($hexstr);
	
	if ($len < 2 || ($len & 0x1) > 0)
		return array();
		
	$out = array_fill(0, $len / 2, 0);
	
	for ($i = 0; $i < $len; $i += 2) {
		$b = hexdec($hexstr[$i]) << 4;
		$b |= hexdec($hexstr[$i+1]) & 0x0f;
		$out[$i/2] = $b;
	}
	
	return $out;
}

function toHex($bytes) {
	return implode('', array_map(function ($n){return ($n < 16 ? "0" : "") . dechex($n);}, $bytes));
}

function uint32ToHex($val) {
	$val &= 0xFFFFFFFF;
	return substr(dechex(0x100000000 + $val), 1);
}

function intval32($value)
{
    $value = ($value & 0xFFFFFFFF);

    if ($value & 0x80000000)
        $value = -((~$value & 0xFFFFFFFF) + 1);

    return $value;
}

// Unsigned right shift (>>>)
function uRShift($a, $b) {
	$a &= 0xFFFFFFFF;
	if($b == 0) return $a;
	return ($a >> $b) & ~(1<<(8 * PHP_INT_SIZE - 1)>>($b-1));
}	

function LShift($a, $b) {
	return ($a << $b) & 0xFFFFFFFF;
}

function Inv($a) {
	return ~$a &  0xFFFFFFFF;
}

function uint32ToBytes($val) {
	$b = array();
	$b[0] = uRShift($val, 6) & 0xFF;
	$b[1] = uRShift($val, 4) & 0xFF;
	$b[2] = uRShift($val, 2) & 0xFF;
	$b[3] = $val & 0xFF;
	return $b;
}
	


