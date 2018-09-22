<?php
// test.php
// Testing the waves_auth module
// By Abdullah Daud, chelahmy@gmail.com
// 22 September 2018


require_once('waves_auth.php');

$tdata = array(
	array( 
		'host' => 'answering.cryptobubbles.club',
		'data' => '0123456789',
		'sig'  => '218WL5u3gP7eE2t2ffpsYpLkyCtK143BbtNY7bHTRDSnGUdzXTjhawBiF9sUoVZwTS61jZbC1Qi7U2xKUDQBJw2F',
		'puk'  => '4GhinWrfkJrLqtgNvLdNZipN2Ha92Z9W3Y1JBo8TLrcf',
		'addr' => '3PCebYRFcYM7CHor5MC5tFfPnBJu7Xv5gsa',
	),
	array( 
		'host' => 'demo.wavesplatform.com',
		'data' => 'Dummy data (JSON, string, numeric)',
		'sig'  => 'Eq3asLdGk1BMi6FHvJBUiuuKj3ox8ZgYmuzPeZnidpU7Fh7o8dHaNybfwcXzwWWuAMEHA3CsPe1NqFtSv8Qhofe',
		'puk'  => 'GAVsV9NiuQVQe1Qj2q3uFLJr8w2Da2yE3MEkBd12GNkA',
		'addr' => '3P6Qow65pqMzpHXbCrK6SwmbGjtMrjPr8Vg',
	),
	array( 
		'host' => 'demo.wavesplatform.com',
		'data' => 'Please visit blindtalk.net and jualla.com',
		'sig'  => '2XbDzTvKJp4LxNzGJDwvF7rtYRcL8G5pphj9M64sHCNekt5HwYaXmE7PRJFWfavzRU5wdVYEwtJNyeLTnrWFTHoL',
		'puk'  => 'CbDnhryczrZRpxDxmvwZndVukYkGV9H17hLXGRKJ8fyx',
		'addr' => '3P9pSqybo9S7tBu83KNG8HK72TZ6dR4DkZ8',
	),
);

foreach ($tdata as $td) {
	$host = $td['host'];
	$data = $td['data'];
	$sig = $td['sig'];
	$puk = $td['puk'];
	$addr = $td['addr'];
	echo "host: $host<br/>";
	echo "data: $data<br/>";
	echo "signature: $sig<br/>";
	echo "public key: $puk<br/>";
	echo "address: $addr<br/><br/>";

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

	echo "<br/>";
}

// Test blake2b with predefined vectors
$handle = fopen("blake2b-kat.txt", "r");

if ($handle) {
	$tests = 0;
	$passes = 0;
	$in = '';
	$key = '';
	$hash = '';
    while (($line = fgets($handle)) !== false) {
        $line = trim($line);
        
        if (strlen($line) > 0) {
        	$parts = explode(':', $line);
        	
        	if (is_array($parts)) {
        		$cnt = count($parts);
        		
        		if ($cnt > 0) {
        			if ($parts[0] == 'in')
        				$in = $cnt > 1 ? trim($parts[$cnt-1]) : '';
        			elseif ($parts[0] == 'key')
        				$key = $cnt > 1 ? trim($parts[$cnt-1]) : '';
        			elseif ($parts[0] == 'hash') {
        				$hash = $cnt > 1 ? trim($parts[$cnt-1]) : '';
        				
						$b2b = new blake2b();	
        				$bh = $b2b->blake2bHex(hex2bytes($in), hex2bytes($key));
        				
        				if ($bh == $hash)
        					++$passes;
        					
        				++$tests;
        			}
        		}
        	}
        }
    }

	echo "Blake2b: " . $passes . " passes of " . $tests . " vector tests<br/>";
	
    fclose($handle);
} else {
    echo "Error: Could not read the blake2b test vectors<br/>";
} 



