package org.ascrypt.utilities
{
	import org.ascrypt.*;
	
	/**
	* General utility functions for byte, array and string data transformation.
	* @author Mika Palmu
	*/
	public class UTIL
	{
		/**
		* Packs bytes to a 32-bit words with given endianness.
		* @param bytes An array of unpacked bytes.
		* @param little Use little endian byte order?
		* @return An array of 32-bit words.
		*/
		public static function pack(bytes:Array, little:Boolean = true):Array
		{
			var w:Array = [];
			var l:int = bytes.length;
			var b1:int, b2:int, b3:int, b4:int;
			for (var i:int = 0; i < l; i += 4)
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
				w[i / 4] = b1 | b2 | b3 | b4;
			}
			return w;
		}
		
		/**
		* Unpacks 32-bit words to bytes with given endianness.
		* @param words An array of 32-bit words.
		* @param little Use little endian byte order?
		* @return An array of unpacked bytes.
		*/
		public static function unpack(words:Array, little:Boolean = true):Array
		{
			var b:Array = [];
			var l:int = words.length;
			var b1:int, b2:int, b3:int, b4:int;
			for (var i:int = 0; i < l; i++)
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
		* @return The formatted string.
		*/
		public static function format(string:String, ...args):String
		{
			var l:int = args.length;
			for (var i:int = 0; i < l; i++)
			{
				var parts:Array = string.split("{" + i + "}");
				string = parts.join(args[i].toString());
			}
			return string;
		}
		
	}
	
}
