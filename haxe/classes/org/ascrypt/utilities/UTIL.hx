package org.ascrypt.utilities;

/**
* General utility functions for byte, array and string data transformation.
* @author Mika Palmu
*/
class UTIL
{
	/**
	* Packs bytes to a 32-bit words with given endianness.
	* @param bytes An array of unpacked bytes.
	* @param little Use little endian byte order?
	* @return An array of 32-bit words.
	*/
	public static inline function pack(bytes:Array<Int>, little:Bool = true):Array<Int>
	{
		var w:Array<Int> = [];
		var l:Int = bytes.length;
		var b1:Int = 0, b2:Int = 0, b3:Int = 0, b4:Int = 0, i:Int = 0;
		while (i < l)
		{
			if (little)
			{
				b1 = bytes[i]; 
				b2 = bytes[i + 1] << 8;
				b3 = bytes[i + 2] << 16;
				b4 = bytes[i + 3] << 24;
			}
			else 
			{
				b1 = bytes[i] << 24; 
				b2 = bytes[i + 1] << 16;
				b3 = bytes[i + 2] << 8; 
				b4 = bytes[i + 3];
			}
			w[Std.int(i / 4)] = b1 | b2 | b3 | b4;
			i += 4;
		}
		return w;
	}
	
	/**
	* Unpacks 32-bit words to bytes with given endianness.
	* @param words An array of 32-bit words.
	* @param little Use little endian byte order?
	* @return An array of unpacked bytes.
	*/
	public static inline function unpack(words:Array<Int>, little:Bool = true):Array<Int>
	{
		var b:Array<Int> = [];
		var l:Int = words.length;
		var b1:Int, b2:Int, b3:Int, b4:Int;
		for (i in 0...l)
		{
			if (little)
			{
				b1 = (words[i] & 0x000000FF);
				b2 = (words[i] & 0x0000FF00) >> 8;
				b3 = (words[i] & 0x00FF0000) >> 16;
				b4 = (words[i] & 0xFF000000) >> 24;
				if (b4 < 0) b4 += 256;
			}
			else
			{
				b1 = (words[i] & 0xFF000000) >> 24;
				b2 = (words[i] & 0x00FF0000) >> 16;
				b3 = (words[i] & 0x0000FF00) >> 8;
				b4 = (words[i] & 0x000000FF);
				if (b1 < 0) b1 += 256;
			}
			b[(i * 4)] = b1; 
			b[(i * 4) + 1] = b2;
			b[(i * 4) + 2] = b3; 
			b[(i * 4) + 3] = b4;
		}
		return b;
	}
	
	/**
	* Inserts the supplied arguments to the string.
	* @param string The original string.
	* @param args The arguments to insert.
	* @return The formatted string.
	*/
	public static inline function format(string:String, args:Array<String>):String
	{
		var l:Int = args.length;
		for (i in 0...l)
		{
			var parts:Array<String> = string.split("{" + i + "}");
			string = parts.join(args[i]);
		}
		return string;
	}
	
}
