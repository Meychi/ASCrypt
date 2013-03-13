<?php

class MD5
{
	/**
	* Computes the MD5 checksum.
	*/	
	public static function compute($text)
	{
		return hash("md5", $text, true);
	}
	
	/**
	* Computes the HMAC for MD5.
	*/
	public static function computeHMAC($key, $text)
	{
		return hash_hmac("md5", $text, $key, true);
	}
	
}

?>
