<?php

class PKCS7 
{
	/**
	* Pads the text with PKCS#7 padding scheme.
	*/
	public static function pad($text, $size)
	{
		$pad = $size - (strlen($text) % $size);
		return $text . str_repeat(chr($pad), $pad);
	}
	
	/**
	* Unpads the text from PKCS#7 padding scheme.
	*/
	public static function unpad($text)
	{
		$pad = ord($text{strlen($text) - 1});
		if ($pad > strlen($text)) return false;
		if (strspn($text, chr($pad), strlen($text) - $pad) != $pad) return false;
		return substr($text, 0, -1 * $pad);
	}

}

?>
