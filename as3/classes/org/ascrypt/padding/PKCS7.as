package org.ascrypt.padding
{
	import org.ascrypt.utilities.*;
	
	/**
	* Pads and unpads data with PKCS#7 padding scheme.
	* @author Mika Palmu
	*/
	public class PKCS7 
	{
		/**
		* Private error messages of the class.
		*/
		private static const ERROR_VALUE:String = "Invalid padding value. Got {0}, expected {1}.";
		
		/**
		* Pads bytes with PKCS#7 padding scheme.
		* @param bytes An array of unpadded bytes.
		* @param size The block size to pad to.
		* @return An array of padded bytes.
		*/
		public static function pad(bytes:Array, size:int):Array
		{
			var c:Array = bytes.concat();
			var s:int = size - c.length % size;
			for (var i:int = 0; i < s; i++) c[c.length] = s;
			return c;
		}
		
		/**
		* Unpads bytes with PKCS#7 padding scheme.
		* @param bytes An array of padded bytes.
		* @return An array of unpadded bytes.
		*/
		public static function unpad(bytes:Array):Array
		{
			var c:Array = bytes.concat();
			var v:int, s:int = c[c.length - 1];
			for (var i:int = s; i > 0; i--)
			{
				v = c[c.length - 1];
				c.length--;
				if (s != v)
				{
					var error:String = UTIL.format(ERROR_VALUE, v, s);
					throw new Error(error);
				}
			}
			return c;
		}
	}
	
}
