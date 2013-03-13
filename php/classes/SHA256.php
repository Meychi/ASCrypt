<?php

class SHA256
{
	/**
	* Computes the SHA-256 checksum.
	*/
	public static function compute($text)
	{
		return hash("sha256", $text, true);
	}
	
	/**
	* Computes the HMAC for SHA-256.
	*/
	public static function computeHMAC($key, $text)
	{
		return hash_hmac("sha256", $text, $key, true);
	}
	
}

?>
