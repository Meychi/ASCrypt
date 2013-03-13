package org.ascrypt
{
	import org.ascrypt.utilities.*;
	
	/**
	* Computes a SHA-1 checksum for the specified data.
	* <br/><br/>SHA-1 is a cryptographic hash function that computes a message digest of 160 bits.
	* @author Mika Palmu
	*/
	public class SHA1
	{
		/**
		* Computes a SHA-1 checksum for the bytes.
		* @param bytes An array of bytes in any encoding.
		* @return An array of SHA-1 computed bytes.
		*/
		public static function compute(bytes:Array):Array
		{
			var b:Array = UTIL.pack(bytes, false);
			return UTIL.unpack(core(b, bytes.length * 8), false);
		}
		
		/**
		* Computes a HMAC-SHA-1 for the key and bytes.
		* @param key An array of bytes in any encoding.
		* @param bytes An array of bytes in any encoding.
		* @return An array of HMAC-SHA-1 hashed bytes.
		*/
		public static function computeHMAC(key:Array, bytes:Array):Array
		{
			return HMAC.compute(key, bytes, SHA1.compute, 64);
		}
		
		/**
		* Private methods of the class.
		*/
		private static function core(x:Array, l:int):Array
		{
			var w:Array = [];
			x[l >> 5] |= 0x80 << (24 - l % 32);
			x[((l + 64 >> 9) << 4) + 15] = l;
			var a:int =  0x67452301;
			var b:int = 0xEFCDAB89, c:int = 0x98BADCFE;
			var d:int = 0x10325476, e:int = 0xC3D2E1F0;
			for (var i:int = 0; i < x.length; i += 16)
			{
				var olda:int = a; 
				var oldb:int = b, oldc:int = c; 
				var oldd:int = d, olde:int = e;
				for (var j:int = 0; j < 80; j++)
				{
					if (j < 16) w[j] = x[i + j] || 0;
					else w[j] = rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
					var t:int = rol(a, 5) + ft(j, b, c, d) + e + w[j] + kt(j);
					e = d; d = c;
					c = rol(b, 30);
					b = a; a = t;
				}
				a += olda; b += oldb;
				c += oldc; d += oldd;
				e += olde;
			}
			return [a, b, c, d, e];
		}
		private static function kt(t:int):int
		{
			return (t < 20) ? 0x5A827999 : (t < 40) ?  0x6ED9EBA1 : (t < 60) ? 0x8F1BBCDC : 0xCA62C1D6;
		}
		private static function ft(t:int, b:int, c:int, d:int):int
		{
			if (t < 20) return (b & c) | ((~b) & d);
			if (t < 40) return b ^ c ^ d;
			if (t < 60) return (b & c) | (b & d) | (c & d);
			return b ^ c ^ d;
		}
		private static function rol(n:int, c:int):int
		{
			return (n << c) | (n >>> (32 - c));
		}
		
	}

}
