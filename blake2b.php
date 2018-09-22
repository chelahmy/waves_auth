<?php
// blake2b.php
// Converted from Waves blake2b.ts
// By Abdullah Daud, chelahmy@gmail.com
// 20 September 2018

// Note: All comments were preserved from the original blake2b.ts.

require_once('utils32.php');

class blake2b {

	// For convenience, let people hash a string, not just a Uint8Array
	function normalizeInput($input) {
		$ret = null;
		if (is_array($input)) {
			$ret = $input;
		} else if (is_string($input)) {
			$ret = str2bytes($input);
		} else {
			throw new Exception("Input must be a string or an array");
		}
		return $ret;
	}

	// Converts a Uint8Array to a hexadecimal string
	// For example, toHex([255, 0, 255]) returns "ff00ff"
	function toHex($bytes) {
		return implode('', array_map(function ($n){return ($n < 16 ? "0" : "") . dechex($n);}, $bytes));
	}

	// Converts any value in [0...2^32-1] to an 8-character hex string
	function uint32ToHex($val) {
		return substr(dechex(4294967296 + $val), 1);
	}

	// 64-bit unsigned addition
	// Sets v[a,a+1] += v[b,b+1]
	// v should be a Uint32Array
	function ADD64AA(&$v, $a, $b) {
		$o0 = $v[$a] + $v[$b];
		$o1 = $v[$a + 1] + $v[$b + 1];
		if ($o0 >= 4294967296) {
			$o1++;
		}
		$v[$a] = $o0 & 0xffffffff;
		$v[$a + 1] = $o1 & 0xffffffff;
	}

	// 64-bit unsigned addition
	// Sets v[a,a+1] += b
	// b0 is the low 32 bits of b, b1 represents the high 32 bits
	function ADD64AC(&$v, $a, $b0, $b1) {
		$o0 = $v[$a] + $b0;
		if ($b0 < 0) {
			$o0 += 4294967296;
		}
		$o1 = $v[$a + 1] + $b1;
		if ($o0 >= 4294967296) {
			$o1++;
		}
		$v[$a] = $o0 & 0xffffffff;
		$v[$a + 1] = $o1 & 0xffffffff;
	}

	// Little-endian byte access
	function B2B_GET32($arr, $i) {
		return $arr[$i] ^ LShift($arr[$i + 1], 8) ^ LShift($arr[$i + 2], 16) ^ LShift($arr[$i + 3], 24);
	}

	// G Mixing function
	// The ROTRs are inlined for speed
	function B2B_G($a, $b, $c, $d, $ix, $iy) {
		$x0 = $this->m[$ix];
		$x1 = $this->m[$ix + 1];
		$y0 = $this->m[$iy];
		$y1 = $this->m[$iy + 1];

		$this->ADD64AA($this->v, $a, $b); // v[a,a+1] += v[b,b+1] ... in JS we must store a uint64 as two uint32s
		$this->ADD64AC($this->v, $a, $x0, $x1); // v[a, a+1] += x ... x0 is the low 32 bits of x, x1 is the high 32 bits

		// v[d,d+1] = (v[d,d+1] xor v[a,a+1]) rotated to the right by 32 bits
		$xor0 = ($this->v[$d] ^ $this->v[$a]) & 0xffffffff;
		$xor1 = ($this->v[$d + 1] ^ $this->v[$a + 1]) & 0xffffffff;
		$this->v[$d] = $xor1;
		$this->v[$d + 1] = $xor0;

		$this->ADD64AA($this->v, $c, $d);

		// v[b,b+1] = (v[b,b+1] xor v[c,c+1]) rotated right by 24 bits
		$xor0 = ($this->v[$b] ^ $this->v[$c]) & 0xffffffff;
		$xor1 = ($this->v[$b + 1] ^ $this->v[$c + 1]) & 0xffffffff;
		$this->v[$b] = (uRShift($xor0, 24) ^ LShift($xor1, 8)) & 0xffffffff;
		$this->v[$b + 1] = (uRShift($xor1, 24) ^ LShift($xor0, 8)) & 0xffffffff;

		$this->ADD64AA($this->v, $a, $b);
		$this->ADD64AC($this->v, $a, $y0, $y1);

		// v[d,d+1] = (v[d,d+1] xor v[a,a+1]) rotated right by 16 bits
		$xor0 = ($this->v[$d] ^ $this->v[$a]) & 0xffffffff;
		$xor1 = ($this->v[$d + 1] ^ $this->v[$a + 1]) & 0xffffffff;
		$this->v[$d] = (uRShift($xor0, 16) ^ LShift($xor1, 16)) & 0xffffffff;
		$this->v[$d + 1] = (uRShift($xor1, 16) ^ LShift($xor0, 16)) & 0xffffffff;

		$this->ADD64AA($this->v, $c, $d);

		// v[b,b+1] = (v[b,b+1] xor v[c,c+1]) rotated right by 63 bits
		$xor0 = ($this->v[$b] ^ $this->v[$c]) & 0xffffffff;
		$xor1 = ($this->v[$b + 1] ^ $this->v[$c + 1]) & 0xffffffff;
		$this->v[$b] = (uRShift($xor1, 31) ^ LShift($xor0, 1)) & 0xffffffff;
		$this->v[$b + 1] = (uRShift($xor0, 31) ^ LShift($xor1, 1)) & 0xffffffff;
	}

	// Initialization Vector
	protected $BLAKE2B_IV32 = [
		0xF3BCC908, 0x6A09E667, 0x84CAA73B, 0xBB67AE85,
		0xFE94F82B, 0x3C6EF372, 0x5F1D36F1, 0xA54FF53A,
		0xADE682D1, 0x510E527F, 0x2B3E6C1F, 0x9B05688C,
		0xFB41BD6B, 0x1F83D9AB, 0x137E2179, 0x5BE0CD19
	];

	protected $SIGMA8 = [
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
		11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
		7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
		9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
		2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
		12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
		13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
		6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
		10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
	];

	// These are offsets into a uint64 buffer.
	// Multiply them all by 2 to make them offsets into a uint32 buffer,
	// because this is Javascript and we don't have uint64s
	protected $SIGMA82;

	// Compression function. 'last' flag indicates last block.
	// Note we're representing 16 uint64s as 32 uint32s
	protected $v;
	protected $m;

	public function __construct () {
		$this->SIGMA82 = array_map(function ($x) {
			return $x * 2;
		}, $this->SIGMA8);
		$this->v = array_fill(0, 32, 0);
		$this->m = array_fill(0, 32, 0);
	}

	function blake2bCompress(&$ctx, $last) {
		// init work variables
		for ($i = 0; $i < 16; $i++) {
			$this->v[$i] = $ctx['h'][$i];
			$this->v[$i + 16] = $this->BLAKE2B_IV32[$i];
		}

		// low 64 bits of offset
		$this->v[24] = $this->v[24] ^ $ctx['t'];
		$this->v[25] = $this->v[25] ^ intval($ctx['t'] / 0x100000000);
		// high 64 bits not supported, offset may not be higher than 2**53-1
		// last block flag set ?
		if ($last) {
			$this->v[28] = ~$this->v[28] & 0xffffffff;
			$this->v[29] = ~$this->v[29] & 0xffffffff;
		}
		
		// get little-endian words
		for ($i = 0; $i < 32; $i++) {
			$this->m[$i] = $this->B2B_GET32($ctx['b'], 4 * $i);
		}

		// twelve rounds of mixing
		for ($i = 0; $i < 12; $i++) {
			$this->B2B_G(0, 8, 16, 24, $this->SIGMA82[$i * 16 + 0], $this->SIGMA82[$i * 16 + 1]);
			$this->B2B_G(2, 10, 18, 26, $this->SIGMA82[$i * 16 + 2], $this->SIGMA82[$i * 16 + 3]);
			$this->B2B_G(4, 12, 20, 28, $this->SIGMA82[$i * 16 + 4], $this->SIGMA82[$i * 16 + 5]);
			$this->B2B_G(6, 14, 22, 30, $this->SIGMA82[$i * 16 + 6], $this->SIGMA82[$i * 16 + 7]);
			$this->B2B_G(0, 10, 20, 30, $this->SIGMA82[$i * 16 + 8], $this->SIGMA82[$i * 16 + 9]);
			$this->B2B_G(2, 12, 22, 24, $this->SIGMA82[$i * 16 + 10], $this->SIGMA82[$i * 16 + 11]);
			$this->B2B_G(4, 14, 16, 26, $this->SIGMA82[$i * 16 + 12], $this->SIGMA82[$i * 16 + 13]);
			$this->B2B_G(6, 8, 18, 28, $this->SIGMA82[$i * 16 + 14], $this->SIGMA82[$i * 16 + 15]);
		}

		for ($i = 0; $i < 16; $i++) {
			$ctx['h'][$i] = ($ctx['h'][$i] ^ $this->v[$i] ^ $this->v[$i + 16]) & 0xffffffff;
		}
	}

	// Creates a BLAKE2b hashing context
	// Requires an output length between 1 and 64 bytes
	// Takes an optional Uint8Array key
	function blake2bInit($outlen, $key) {
		if ($outlen === 0 || $outlen > 64) {
			throw new Exception('Illegal output length, expected 0 < length <= 64');
		}
		if (is_array($key) && (count($key) <= 0 || count($key) > 64)) {
			throw new Exception('Illegal key, expected array with 0 < length <= 64');
		}

		// state, 'param block'
		$ctx = array(
			'b' => array_fill(0, 128, 0),
			'h' => array_fill(0, 16, 0),
			't' => 0, // input count
			'c' => 0, // pointer within buffer
			'outlen' => $outlen // output length in bytes
		);

		// initialize hash state
		for ($i = 0; $i < 16; $i++) {
			$ctx['h'][$i] = $this->BLAKE2B_IV32[$i];
		}
		
		$keylen = is_array($key) ? count($key) : 0;
		$ctx['h'][0] ^= 0x01010000 ^ ($keylen << 8) ^ $outlen;

		// key the hash, if applicable
		if (is_array($key)) {
			$this->blake2bUpdate($ctx, $key);
			// at the end
			$ctx['c'] = 128;
		}

		return $ctx;
	}

	// Updates a BLAKE2b streaming hash
	// Requires hash context and Uint8Array (byte array)
	function blake2bUpdate(&$ctx, $input) {
		for ($i = 0; $i < count($input); $i++) {
			if ($ctx['c'] === 128) { // buffer full ?
				$ctx['t'] += $ctx['c']; // add counters
				$this->blake2bCompress($ctx, false); // compress (not last)
				$ctx['c'] = 0; // counter to zero
			}
			$ctx['b'][$ctx['c']++] = $input[$i];
		}
	}

	// Completes a BLAKE2b streaming hash
	// Returns a Uint8Array containing the message digest
	function blake2bFinal(&$ctx) {
		$ctx['t'] += $ctx['c']; // mark last block offset
		while ($ctx['c'] < 128) { // fill up with zeros
			$ctx['b'][$ctx['c']++] = 0;
		}
		$this->blake2bCompress($ctx, true); // final block flag = 1
		// little endian convert and store
		$out = array_fill(0, $ctx['outlen'], 0);
		for ($i = 0; $i < $ctx['outlen']; $i++) {
			$out[$i] = ($ctx['h'][$i >> 2] >> (8 * ($i & 3))) & 0xff;
		}
		return $out;
	}

	// Computes the BLAKE2B hash of a string or byte array, and returns a Uint8Array
	//
	// Returns a n-byte Uint8Array
	//
	// Parameters:
	// - input - the input bytes, as a string, Buffer or Uint8Array
	// - key - optional key Uint8Array, up to 64 bytes
	// - outlen - optional output length in bytes, default 64
	function blake2b($input, $key, $outlen = 64) {
		// preprocess inputs
		$input = $this->normalizeInput($input);
		// do the math
		$ctx = $this->blake2bInit($outlen, $key);
		$this->blake2bUpdate($ctx, $input);
		return $this->blake2bFinal($ctx);
	}

	// Computes the BLAKE2B hash of a string or byte array
	//
	// Returns an n-byte hash in hex, all lowercase
	//
	// Parameters:
	// - input - the input bytes, as a string, Buffer, or Uint8Array
	// - key - optional key Uint8Array, up to 64 bytes
	// - outlen - optional output length in bytes, default 64
	function blake2bHex($input, $key, $outlen = 64) {
		$output = $this->blake2b($input, $key, $outlen);
		return $this->toHex($output);
	}

}
