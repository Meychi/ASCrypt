<?php

class AES
{
	/**
	* Encrypts text with AES-128/192/256 algorithm.
	*/
	public static function encrypt($key, $text, $mode = "ecb", $iv = null) 
	{
		$size = MCRYPT_RIJNDAEL_128; // AES fixed to 128 bits
		if (isset($iv)) return mcrypt_encrypt($size, $key, $text, $mode, $iv);
		else return @mcrypt_encrypt($size, $key, $text, $mode);
	}
	
	/**
	* Decrypts text with AES-128/192/256 algorithm.
	*/
	public static function decrypt($key, $text, $mode = "ecb", $iv = null)
	{
		$size = MCRYPT_RIJNDAEL_128; // AES fixed to 128 bits
		if (isset($iv)) return mcrypt_decrypt($size, $key, $text, $mode, $iv);
		return @mcrypt_decrypt($size, $key, $text, $mode);
	}
	
}

?>
