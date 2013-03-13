<?php

class SHA1
{
	/**
	* Computes the SHA-1 checksum.
	*/
	public static function compute($text)
	{
		return hash("sha1", $text, true);
	}
	
	/**
	* Computes the HMAC for SHA-1.
	*/
	public static function computeHMAC($key, $text)
	{
		return hash_hmac("sha1", $text, $key, true);
	}
	
}

?>
