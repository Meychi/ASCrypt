<?php

class ROT13 
{
	/**
	* Encodes text with ROT13 algorithm.
	*/
	public static function encode($text)
	{
		return str_rot13($text);
	}
	
	/**
	* Decodes text with ROT13 algorithm.
	*/
	public static function decode($text)
	{
		return str_rot13($text);
	}
	
}

?>
