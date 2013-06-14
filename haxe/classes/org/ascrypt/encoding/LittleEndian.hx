package org.ascrypt.encoding;

/**
* Converts bytes and text in UTF-16 LE encoding.
* @author Mika Palmu
*/
class LittleEndian
{
	/**
	* Converts text to an array of bytes.
	* @param text An ASCII or UTF-8 encoded string.
	* @return An array of UTF-16 LE bytes.
	*/
	public static inline function textToBytes(text:String):Array<Int>
	{
		var b:Array<Int> = [];
		var i:Int = 0, l:Int = text.length * 2;
		while (i < l)
		{
			b[i] = text.charCodeAt(Std.int(i / 2)) & 0xFF;
			b[i + 1] = (text.charCodeAt(Std.int(i / 2)) >>> 8) & 0xFF;
			i += 2;
		}
		return b;
	}
	
	/**
	* Converts an array of bytes to text.
	* @param bytes An array of UTF-16 LE bytes.
	* @return An UTF-16 LE encoded string.
	*/
	public static inline function bytesToText(bytes:Array<Int>):String
	{
		var l:Int = bytes.length;
		var c:Int, i:Int = 0, s:String = "";
		while (i < l)
		{
			c = (bytes[i] & 0xFF) | (bytes[i + 1] << 8);
			s += String.fromCharCode(c);
			i += 2;
		}
		return s;
	}
	
}
