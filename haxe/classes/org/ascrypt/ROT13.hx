package org.ascrypt;

/**
* Encodes and decodes bytes with ROT13 algorithm.
* ROT13 is a simple variation of the Caesar cipher, developed in ancient Rome.
* @author Mika Palmu
*/
class ROT13 
{
	/**
	* Characters used in the ROT13 calculation.
	*/
	private static var chrs:String = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMabcdefghijklmnopqrstuvwxyzabcdefghijklm";
	
	/**
	* Encodes bytes with ROT13 algorithm.
	* @param bytes An array of ASCII or UTF-8 bytes.
	* @return An array of encoded bytes.
	*/
	public static function encode(bytes:Array<Int>):Array<Int>
	{
		return core(bytes);
	}
	
	/**
	* Decodes bytes with ROT13 algorithm.
	* @param bytes An array of ASCII or UTF-8 bytes.
	* @return An array of decoded bytes.
	*/
	public static function decode(bytes:Array<Int>):Array<Int>
	{
		return core(bytes);
	}
	
	/**
	* Private methods of the class.
	*/
	private static function core(b:Array<Int>):Array<Int>
	{
		var c:String, r:Array<Int> = [];
		var p:Int, l:Int = b.length;
		for (i in 0...l)
		{
			c = String.fromCharCode(b[i]);
			p = chrs.indexOf(c); // Position in chrs...
			if (p > -1) r[i] = chrs.charCodeAt(p + 13);
			else r[i] = b[i];
		}
		return r;
	}
	
}
