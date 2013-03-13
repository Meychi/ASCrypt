<?php

// NOTE: This implementation resets the state every time.

class ARC4
{
	/**
	* Encrypts text with ARC4 algorithm.
	*/
	public static function encrypt($key, $text)
	{
		$iv	= ""; // Empty init vector...
		return mcrypt_encrypt(MCRYPT_ARCFOUR, $key, $text, MCRYPT_MODE_STREAM, $iv);
	}
	
	/**
	* Decrypts text with ARC4 algorithm.
	*/
	public static function decrypt($key, $text)
	{
		$iv	= ""; // Empty init vector...
		return mcrypt_decrypt(MCRYPT_ARCFOUR, $key, $text, MCRYPT_MODE_STREAM, $iv);
	}
	
}

?> 
