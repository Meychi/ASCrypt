<?php

class XXTEA
{
	/**
	* Encrypts text with XXTEA algorithm.
	*/	
	public static function encrypt($key, $text)
	{
		$k = XXTEA::str2long($key);
		$v = XXTEA::str2long($text);
		if (count($v) <= 1) $v[1] = 0;
		$n = count($v); $z = $v[$n - 1]; $y = $v[0]; $d = 0x9E3779B9;
		$m = 0; $e = 0; $s = 0; $q = floor(6 + 52 / $n);
		while ($q-- > 0) 
		{
			$s = XXTEA::int32($s + $d);
			$e = XXTEA::urshift($s, 2) & 3;
			for ($i = 0; $i < $n; $i++)
			{
				$y = $v[($i + 1) % $n];
				$m = XXTEA::int32((XXTEA::urshift($z, 5) ^ $y << 2) + (XXTEA::urshift($y, 3) ^ $z << 4)) ^ XXTEA::int32(($s ^ $y) + ($k[$i & 3 ^ $e] ^ $z));
				$z = $v[$i] = XXTEA::int32($v[$i] + $m);
			}
		}
		return XXTEA::long2str($v);
	}
	
	/**
	* Decrypts text with XXTEA algorithm.
	*/
	public static function decrypt($key, $text)
	{
		$k = XXTEA::str2long($key);
		$v = XXTEA::str2long($text);
		$n = count($v); $z = $v[$n - 1]; $y = $v[0]; $d = 0x9E3779B9;
		$m = 0; $e = 0; $q = floor(6 + 52 / $n); $s = $q * $d;
		while ($s != 0) 
		{
			$e = XXTEA::urshift($s, 2) & 3;
			for ($i = $n - 1; $i >= 0; $i--) 
			{
				$z = $v[$i > 0 ? $i - 1 : $n - 1];
				$m = XXTEA::int32((XXTEA::urshift($z, 5) ^ $y << 2) + (XXTEA::urshift($y, 3) ^ $z << 4)) ^ XXTEA::int32(($s ^ $y) + ($k[$i & 3 ^ $e] ^ $z));
				$y = $v[$i] = XXTEA::int32($v[$i] - $m);
			}
			$s = XXTEA::int32($s - $d);
		}
		return XXTEA::long2str($v);
	}
	
	/**
    * Converts string to long array.
	*/
    private static function str2long($s)
	{
		return array_values(unpack("V*", $s));
    }
	
	/**
    * Converts long array to string.
    */
    private static function long2str($v) 
	{
        $s = "";
        for ($i = 0; $i < count($v); $i++) 
		{
			$s .= pack("V", $v[$i]);
		}
		return $s;
    }
	
	/**
	* HACK: Unsigned right shift.
	*/
	private static function urshift($i, $n)
	{
		if (0xffffffff < $i || -0xffffffff > $i) 
		{
			$i = fmod($i, 0xffffffff + 1);
		}
		if (0x7fffffff < $i) $i -= 0xffffffff + 1.0;
		else if (-0x80000000 > $i) $i += 0xffffffff + 1.0;
		if (0 > $i)
		{
			$i &= 0x7fffffff;
			$i >>= $n;
			$i |= 1 << (31 - $n);
		} 
		else $i >>= $n;
		return $i;
	}
	
    /**
    * HACK: Fixes overflow problem.
    */
    private static function int32($n) 
	{
        while ($n >= 2147483648) $n -= 4294967296;
        while ($n <= -2147483649) $n += 4294967296;
        return (int)$n;
    }
	
}

?>
