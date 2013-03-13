<?php

class RMD160
{
	/**
	* Computes the RIPEMD-160 checksum.
	*/	
	public static function compute($text)
	{
		return hash("ripemd160", $text, true);
	}
	
	/**
	* Computes the HMAC for RIPEMD-160.
	*/
	public static function computeHMAC($key, $text)
	{
		return hash_hmac("ripemd160", $text, $key, true);
	}
	
}

?>
