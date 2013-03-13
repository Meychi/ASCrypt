<?php

class Base16 
{
	/**
	* Encodes text to base16 string.
	*/	
	public static function encode($text)
	{
		return bin2hex($text);
	}
	
	/**
	* Decodes base16 string to text.
	*/
	public static function decode($base16)
	{
		return pack("H*", $base16);
	}
	
}

?>
