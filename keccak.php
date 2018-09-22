<?php
// keccak.php
// The keccak digest routine extracted and converted from Waves sha3.ts
// By Abdullah Daud, chelahmy@gmail.com
// 22 September 2018

// Note:
// The original typescript codes sha3.ts handles keccak and other routines.
// Sha3 itself originates from keccak. Waves uses keccak and blake2b to
// validate addresses, and to generate addresses from public keys.

require_once('utils32.php');

class keccak {
	protected $KECCAK_PADDING = [1, 256, 65536, 16777216];
	protected $SHIFT = [0, 8, 16, 24];
	protected $RC = [1, 0, 32898, 0, 32906, 2147483648, 2147516416, 2147483648, 32907, 0, 2147483649, 0, 2147516545, 2147483648, 32777, 2147483648, 138, 0, 136, 0, 2147516425, 0, 2147483658, 0, 2147516555, 0, 139, 2147483648, 32905, 2147483648, 32771, 2147483648, 32770, 2147483648, 128, 2147483648, 32778, 0, 2147483658, 2147483648, 2147516545, 2147483648, 32896, 2147483648, 2147483649, 0, 2147516424, 2147483648];

	private $blocks = [];
	private $s = [];
	private $padding = [];
	private $outputBits = 256;
	private $reset = true;
	private $block = 0;
	private $start = 0;
	private $blockCount = 0;
	private $byteCount = 0;
	private $outputBlocks = 0;
	private $extraBytes = 0;
	private $lastByteIndex = 0;

	// Supported bits 224, 256, 384, 512
	public function __construct ($bits = 256) {		
		$padding = $this->KECCAK_PADDING; 
		$outputBits = $bits;
		
		$this->blocks = [];
		$this->s = [];
		$this->padding = $padding;
		$this->outputBits = $outputBits;
		$this->reset = true;
		$this->block = 0;
		$this->start = 0;
		$this->blockCount = 1600 - ($bits << 1) >> 5;
		$this->byteCount = $this->blockCount << 2;
		$this->outputBlocks = $outputBits >> 5;
		$this->extraBytes = ($outputBits & 31) >> 3;
		
		for ($i = 0; $i < 50; ++$i) {
			$this->s[$i] = 0;
		}
		
		$this->lastByteIndex = 0;
	}
	
	protected function update($message) {
		$notString = !is_string($message);
		//if (notString && message.constructor === ArrayBuffer) {
		//	message = new Uint8Array(message)
		//}
		if (!$notString)
			$length = strlen($message);
		else
			$length = count($message);
		$blocks = &$this->blocks;
		$byteCount = $this->byteCount;
		$blockCount = $this->blockCount;
		$index = 0;
		$s = &$this->s;
		//i, code;
		while ($index < $length) {
			if ($this->reset) {
				$this->reset = false;
				$blocks[0] = &$this->block;
				for ($i = 1; $i < $blockCount + 1; ++$i) {
					$blocks[$i] = 0;
				}
			}
			if ($notString) {
				for ($i = $this->start; $index < $length && $i < $byteCount; ++$index) {
					$blocks[$i >> 2] |= $message[$index] << $this->SHIFT[$i++ & 3];
				}
			} else {
				for ($i = $this->start; $index < $length && $i < $byteCount; ++$index) {
					$code = ord($message[$index]);
					if ($code < 128) {
						$blocks[$i >> 2] |= $code << $this->SHIFT[$i++ & 3];
					} else if ($code < 2048) {
						$blocks[$i >> 2] |= (192 | $code >> 6) << $this->SHIFT[$i++ & 3];
						$blocks[$i >> 2] |= (128 | $code & 63) << $this->SHIFT[$i++ & 3];
					} else if ($code < 55296 || $code >= 57344) {
						$blocks[$i >> 2] |= (224 | $code >> 12) << $this->SHIFT[$i++ & 3];
						$blocks[$i >> 2] |= (128 | $code >> 6 & 63) << $this->SHIFT[$i++ & 3];
						$blocks[$i >> 2] |= (128 | $code & 63) << $this->SHIFT[$i++ & 3];
					} else {
						$code = 65536 + (($code & 1023) << 10 | ord($message[++$index]) & 1023);
						$blocks[$i >> 2] |= (240 | $code >> 18) << $this->SHIFT[$i++ & 3];
						$blocks[$i >> 2] |= (128 | $code >> 12 & 63) << $this->SHIFT[$i++ & 3];
						$blocks[$i >> 2] |= (128 | $code >> 6 & 63) << $this->SHIFT[$i++ & 3];
						$blocks[$i >> 2] |= (128 | $code & 63) << $this->SHIFT[$i++ & 3];
					}	
				}
			}
			$this->lastByteIndex = $i;
			if ($i >= $byteCount) {
				$this->start = $i - $byteCount;
				$this->block = $blocks[$blockCount];
				for ($i = 0; $i < $blockCount; ++$i) {
					$s[$i] ^= $blocks[$i];
				}
				$this->f($s);
				$this->reset = true;
			} else {
				$this->start = $i;
			}
		}
		return $this;
	}

	protected function finalize() {
		$blocks = &$this->blocks;
		$i = $this->lastByteIndex;
		$blockCount = $this->blockCount;
		$s = &$this->s;
		$blocks[$i >> 2] |= $this->padding[$i & 3];
		if ($this->lastByteIndex === $this->byteCount) {
			$blocks[0] = $blocks[$blockCount];
			for ($i = 1; $i < $blockCount + 1; ++$i) {
				$blocks[$i] = 0;
			}
		}
		$blocks[$blockCount - 1] |= 2147483648;
		for ($i = 0; $i < $blockCount; ++$i) {
			$s[$i] ^= $blocks[$i];
		}
		$this->f($s);
	}

	public function digest($message) {
		$this->update($message);
		$this->finalize();
		$blockCount = $this->blockCount;
		$s = &$this->s;
		$outputBlocks = $this->outputBlocks;
		$extraBytes = $this->extraBytes;
		$i = 0;
		$j = 0;
		$_array = [];
		//var offset, block;
		while ($j < $outputBlocks) {
			for ($i = 0; $i < $blockCount && $j < $outputBlocks; ++$i, ++$j) {
				$offset = $j << 2;
				$block = $s[$i];
				$_array[$offset] = $block & 255;
				$_array[$offset + 1] = $block >> 8 & 255;
				$_array[$offset + 2] = $block >> 16 & 255;
				$_array[$offset + 3] = $block >> 24 & 255;
			}
			if ($j % $blockCount === 0) {
				$this->f($s);
			}
		}
		if ($extraBytes) {
			$offset = $j << 2;
			$block = $s[$i];
			if ($extraBytes > 0) {
				$_array[$offset] = $block & 255;
			}
			if ($extraBytes > 1) {
				$_array[$offset + 1] = $block >> 8 & 255;
			}
			if ($extraBytes > 2) {
				$_array[$offset + 2] = $block >> 16 & 255;
			}
		}
		return $_array;
	}

	protected function f(&$s) {
		//var h, l, n, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16, b17, b18, b19, b20, b21, b22, b23, b24, b25, b26, b27, b28, b29, b30, b31, b32, b33, b34, b35, b36, b37, b38, b39, b40, b41, b42, b43, b44, b45, b46, b47, b48, b49;
		for ($n = 0; $n < 48; $n += 2) {
			$c0 = $s[0] ^ $s[10] ^ $s[20] ^ $s[30] ^ $s[40];
			$c1 = $s[1] ^ $s[11] ^ $s[21] ^ $s[31] ^ $s[41];
			$c2 = $s[2] ^ $s[12] ^ $s[22] ^ $s[32] ^ $s[42];
			$c3 = $s[3] ^ $s[13] ^ $s[23] ^ $s[33] ^ $s[43];
			$c4 = $s[4] ^ $s[14] ^ $s[24] ^ $s[34] ^ $s[44];
			$c5 = $s[5] ^ $s[15] ^ $s[25] ^ $s[35] ^ $s[45];
			$c6 = $s[6] ^ $s[16] ^ $s[26] ^ $s[36] ^ $s[46];
			$c7 = $s[7] ^ $s[17] ^ $s[27] ^ $s[37] ^ $s[47];
			$c8 = $s[8] ^ $s[18] ^ $s[28] ^ $s[38] ^ $s[48];
			$c9 = $s[9] ^ $s[19] ^ $s[29] ^ $s[39] ^ $s[49];
			$h = $c8 ^ (LShift($c2, 1) | uRShift($c3, 31));
			$l = $c9 ^ (LShift($c3, 1) | uRShift($c2, 31));
			$s[0] ^= $h;
			$s[1] ^= $l;
			$s[10] ^= $h;
			$s[11] ^= $l;
			$s[20] ^= $h;
			$s[21] ^= $l;
			$s[30] ^= $h;
			$s[31] ^= $l;
			$s[40] ^= $h;
			$s[41] ^= $l;
			$h = $c0 ^ (LShift($c4, 1) | uRShift($c5, 31));
			$l = $c1 ^ (LShift($c5, 1) | uRShift($c4, 31));
			$s[2] ^= $h;
			$s[3] ^= $l;
			$s[12] ^= $h;
			$s[13] ^= $l;
			$s[22] ^= $h;
			$s[23] ^= $l;
			$s[32] ^= $h;
			$s[33] ^= $l;
			$s[42] ^= $h;
			$s[43] ^= $l;
			$h = $c2 ^ (LShift($c6, 1) | uRShift($c7, 31));
			$l = $c3 ^ (LShift($c7, 1) | uRShift($c6, 31));
			$s[4] ^= $h;
			$s[5] ^= $l;
			$s[14] ^= $h;
			$s[15] ^= $l;
			$s[24] ^= $h;
			$s[25] ^= $l;
			$s[34] ^= $h;
			$s[35] ^= $l;
			$s[44] ^= $h;
			$s[45] ^= $l;
			$h = $c4 ^ (LShift($c8, 1) | uRShift($c9, 31));
			$l = $c5 ^ (LShift($c9, 1) | uRShift($c8, 31));
			$s[6] ^= $h;
			$s[7] ^= $l;
			$s[16] ^= $h;
			$s[17] ^= $l;
			$s[26] ^= $h;
			$s[27] ^= $l;
			$s[36] ^= $h;
			$s[37] ^= $l;
			$s[46] ^= $h;
			$s[47] ^= $l;
			$h = $c6 ^ (LShift($c0, 1) | uRShift($c1, 31));
			$l = $c7 ^ (LShift($c1, 1) | uRShift($c0, 31));
			$s[8] ^= $h;
			$s[9] ^= $l;
			$s[18] ^= $h;
			$s[19] ^= $l;
			$s[28] ^= $h;
			$s[29] ^= $l;
			$s[38] ^= $h;
			$s[39] ^= $l;
			$s[48] ^= $h;
			$s[49] ^= $l;
			$b0 = $s[0];
			$b1 = $s[1];
			$b32 = LShift($s[11], 4) | uRShift($s[10], 28);
			$b33 = LShift($s[10], 4) | uRShift($s[11], 28);
			$b14 = LShift($s[20], 3) | uRShift($s[21], 29);
			$b15 = LShift($s[21], 3) | uRShift($s[20], 29);
			$b46 = LShift($s[31], 9) | uRShift($s[30], 23);
			$b47 = LShift($s[30], 9) | uRShift($s[31], 23);
			$b28 = LShift($s[40], 18) | uRShift($s[41], 14);
			$b29 = LShift($s[41], 18) | uRShift($s[40], 14);
			$b20 = LShift($s[2], 1) | uRShift($s[3], 31);
			$b21 = LShift($s[3], 1) | uRShift($s[2], 31);
			$b2 = LShift($s[13], 12) | uRShift($s[12], 20);
			$b3 = LShift($s[12], 12) | uRShift($s[13], 20);
			$b34 = LShift($s[22], 10) | uRShift($s[23], 22);
			$b35 = LShift($s[23], 10) | uRShift($s[22], 22);
			$b16 = LShift($s[33], 13) | uRShift($s[32], 19);
			$b17 = LShift($s[32], 13) | uRShift($s[33], 19);
			$b48 = LShift($s[42], 2) | uRShift($s[43], 30);
			$b49 = LShift($s[43], 2) | uRShift($s[42], 30);
			$b40 = LShift($s[5], 30) | uRShift($s[4], 2);
			$b41 = LShift($s[4], 30) | uRShift($s[5], 2);
			$b22 = LShift($s[14], 6) | uRShift($s[15], 26);
			$b23 = LShift($s[15], 6) | uRShift($s[14], 26);
			$b4 = LShift($s[25], 11) | uRShift($s[24], 21);
			$b5 = LShift($s[24], 11) | uRShift($s[25], 21);
			$b36 = LShift($s[34], 15) | uRShift($s[35], 17);
			$b37 = LShift($s[35], 15) | uRShift($s[34], 17);
			$b18 = LShift($s[45], 29) | uRShift($s[44], 3);
			$b19 = LShift($s[44], 29) | uRShift($s[45], 3);
			$b10 = LShift($s[6], 28) | uRShift($s[7], 4);
			$b11 = LShift($s[7], 28) | uRShift($s[6], 4);
			$b42 = LShift($s[17], 23) | uRShift($s[16], 9);
			$b43 = LShift($s[16], 23) | uRShift($s[17], 9);
			$b24 = LShift($s[26], 25) | uRShift($s[27], 7);
			$b25 = LShift($s[27], 25) | uRShift($s[26], 7);
			$b6 = LShift($s[36], 21) | uRShift($s[37], 11);
			$b7 = LShift($s[37], 21) | uRShift($s[36], 11);
			$b38 = LShift($s[47], 24) | uRShift($s[46], 8);
			$b39 = LShift($s[46], 24) | uRShift($s[47], 8);
			$b30 = LShift($s[8], 27) | uRShift($s[9], 5);
			$b31 = LShift($s[9], 27) | uRShift($s[8], 5);
			$b12 = LShift($s[18], 20) | uRShift($s[19], 12);
			$b13 = LShift($s[19], 20) | uRShift($s[18], 12);
			$b44 = LShift($s[29], 7) | uRShift($s[28], 25);
			$b45 = LShift($s[28], 7) | uRShift($s[29], 25);
			$b26 = LShift($s[38], 8) | uRShift($s[39], 24);
			$b27 = LShift($s[39], 8) | uRShift($s[38], 24);
			$b8 = LShift($s[48], 14) | uRShift($s[49], 18);
			$b9 = LShift($s[49], 14) | uRShift($s[48], 18);
			$s[0] = $b0 ^ Inv($b2) & $b4;
			$s[1] = $b1 ^ Inv($b3) & $b5;
			$s[10] = $b10 ^ Inv($b12) & $b14;
			$s[11] = $b11 ^ Inv($b13) & $b15;
			$s[20] = $b20 ^ Inv($b22) & $b24;
			$s[21] = $b21 ^ Inv($b23) & $b25;
			$s[30] = $b30 ^ Inv($b32) & $b34;
			$s[31] = $b31 ^ Inv($b33) & $b35;
			$s[40] = $b40 ^ Inv($b42) & $b44;
			$s[41] = $b41 ^ Inv($b43) & $b45;
			$s[2] = $b2 ^ Inv($b4) & $b6;
			$s[3] = $b3 ^ Inv($b5) & $b7;
			$s[12] = $b12 ^ Inv($b14) & $b16;
			$s[13] = $b13 ^ Inv($b15) & $b17;
			$s[22] = $b22 ^ Inv($b24) & $b26;
			$s[23] = $b23 ^ Inv($b25) & $b27;
			$s[32] = $b32 ^ Inv($b34) & $b36;
			$s[33] = $b33 ^ Inv($b35) & $b37;
			$s[42] = $b42 ^ Inv($b44) & $b46;
			$s[43] = $b43 ^ Inv($b45) & $b47;
			$s[4] = $b4 ^ Inv($b6) & $b8;
			$s[5] = $b5 ^ Inv($b7) & $b9;
			$s[14] = $b14 ^ Inv($b16) & $b18;
			$s[15] = $b15 ^ Inv($b17) & $b19;
			$s[24] = $b24 ^ Inv($b26) & $b28;
			$s[25] = $b25 ^ Inv($b27) & $b29;
			$s[34] = $b34 ^ Inv($b36) & $b38;
			$s[35] = $b35 ^ Inv($b37) & $b39;
			$s[44] = $b44 ^ Inv($b46) & $b48;
			$s[45] = $b45 ^ Inv($b47) & $b49;
			$s[6] = $b6 ^ Inv($b8) & $b0;
			$s[7] = $b7 ^ Inv($b9) & $b1;
			$s[16] = $b16 ^ Inv($b18) & $b10;
			$s[17] = $b17 ^ Inv($b19) & $b11;
			$s[26] = $b26 ^ Inv($b28) & $b20;
			$s[27] = $b27 ^ Inv($b29) & $b21;
			$s[36] = $b36 ^ Inv($b38) & $b30;
			$s[37] = $b37 ^ Inv($b39) & $b31;
			$s[46] = $b46 ^ Inv($b48) & $b40;
			$s[47] = $b47 ^ Inv($b49) & $b41;
			$s[8] = $b8 ^ Inv($b0) & $b2;
			$s[9] = $b9 ^ Inv($b1) & $b3;
			$s[18] = $b18 ^ Inv($b10) & $b12;
			$s[19] = $b19 ^ Inv($b11) & $b13;
			$s[28] = $b28 ^ Inv($b20) & $b22;
			$s[29] = $b29 ^ Inv($b21) & $b23;
			$s[38] = $b38 ^ Inv($b30) & $b32;
			$s[39] = $b39 ^ Inv($b31) & $b33;
			$s[48] = $b48 ^ Inv($b40) & $b42;
			$s[49] = $b49 ^ Inv($b41) & $b43;
			$s[0] ^= $this->RC[$n];
			$s[1] ^= $this->RC[$n + 1];
		}
	}
}
