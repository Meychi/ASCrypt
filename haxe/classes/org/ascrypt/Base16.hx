package org.ascrypt;

/**
* Encodes and decodes data with base16 (hex) encoding.
* Base16 is hexadecimal representation of binary data that only uses characters A-Z, a-z, and 0-9.
* @author Mika Palmu
*/
class Base16
{
	/**
	* Encodes bytes to a base16 string.
	* @param bytes An array of ASCII or UTF-8 bytes.
	* @return An encoded base16 string.
	*/
	public static function encode(bytes:Array<Int>):String
	{
		var l:Int = bytes.length;
		var v:String, h:Array<String> = [];
		for (i in 0...l)
		{
			v = StringTools.hex(bytes[i]).toLowerCase();
			if (v.length < 2) h[i] = "0" + v;
			else h[i] = v;
		}
		return h.join("");
	}
	
	/**
	* Decodes base16 string to bytes.
	* @param text A base16 encoded string.
	* @return An array of decoded bytes.
	*/
	public static function decode(text:String):Array<Int>
	{
		var i:Int = 0;
		var l:Int = text.length;
		var v:String, b:Array<Int> = [];
		while (i < l)
		{
			v = text.substr(i, 2);
			b[Std.int(i / 2)] = Std.parseInt("0x" + v);
			i += 2;
		}
		return b;
	}
	
}
