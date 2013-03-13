<?php

class Base64 
{
	/**
	* Encodes text to base64 string.
	*/	
	public static function encode($text)
	{
		return base64_encode($text);
	}
	
	/**
	* Decodes base64 string to text.
	*/
	public static function decode($base64)
	{
		return base64_decode($base64);
	}
	
}

?>
