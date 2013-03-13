<?php

class GUID 
{
	/**
	* Creates a new GUID with MD5 from unique data.
	*/
	public static function create()
	{	
		$r = "";
		$i = uniqid(rand(), true);
		$g = hash("md5", $i, false);
		$r .= substr($g, 0, 8) . "-";
		$r .= substr($g, 8, 4) . "-";
		$r .= substr($g, 12, 4) . "-";
		$r .= substr($g, 16, 4) . "-";
		$r .= substr($g, 20, 12);
		return $r;
	}
	
}

?>
