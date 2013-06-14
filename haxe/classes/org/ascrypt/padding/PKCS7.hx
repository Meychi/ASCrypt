package org.ascrypt.padding;

import org.ascrypt.utilities.UTIL;

/**
* Pads and unpads data with PKCS#7 padding scheme.
* @author Mika Palmu
*/
class PKCS7 
{
	/**
	* Private error messages of the class.
	*/
	private static var ERROR_VALUE:String = "Invalid padding value. Got {0}, expected {1}.";
	
	/**
	* Pads bytes with PKCS#7 padding scheme.
	* @param bytes An array of unpadded bytes.
	* @param size The block size to pad to.
	* @return An array of padded bytes.
	*/
	public static function pad(bytes:Array<Int>, size:Int):Array<Int>
	{
		var c:Array<Int> = bytes.concat([]);
		var s:Int = size - c.length % size;
		for (i in 0...s) c[c.length] = s;
		return c;
	}
	
	/**
	* Unpads bytes with PKCS#7 padding scheme.
	* @param bytes An array of padded bytes.
	* @return An array of unpadded bytes.
	*/
	public static function unpad(bytes:Array<Int>):Array<Int>
	{
		var c:Array<Int> = bytes.concat([]);
		var v:Int, s:Int = c[c.length - 1];
		for (i in 0...s)
		{
			v = c[c.length - 1]; c.pop();
			if (s != v) throw UTIL.format(ERROR_VALUE, [Std.string(v), Std.string(s)]);
		}
		return c;
	}
	
}
