<?php

class ZEROS
{
	/**
	* Pads the text with zero byte padding scheme.
	*/
	public static function pad($text, $size) 
	{
		$c = $size - (strlen($text) % $size);
		return $text . str_repeat("\0", $c);
	}
	
	/**
	* Unpads the text with zero byte padding scheme.
	*/
	public static function unpad($text)
	{
		return rtrim($text, "\0");
	}

}

?>
