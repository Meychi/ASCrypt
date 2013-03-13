import org.ascrypt.utilities.*;

/**
* Computes a SHA-1 checksum for the specified data.
* <br/><br/>SHA-1 is a cryptographic hash function that computes a message digest of 160 bits.
* @author Mika Palmu
*/
class org.ascrypt.SHA1
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
	private static function core(x:Array, l:Number):Array
	{
		x[l >> 5] |= 0x80 << (24 - l % 32);
		x[((l + 64 >> 9) << 4) + 15] = l;
		var w:Array = [], a:Number = 1732584193;
		var b:Number = -271733879, c:Number = -1732584194;
		var d:Number = 271733878, e:Number = -1009589776;
		for (var i:Number = 0; i < x.length; i += 16) 
		{
			var olda:Number = a, oldb:Number = b;
			var oldc:Number = c, oldd:Number = d, olde:Number = e;
			for (var j:Number = 0; j < 80; j++) 
			{
				if (j < 16) w[j] = x[i + j];
				else w[j] = rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
				var t:Number = add(add(rol(a, 5), ft(j, b, c, d)), add(add(e, w[j]), kt(j)));
				e = d; d = c; c = rol(b, 30); b = a; a = t;
			}
			a = add(a, olda); b = add(b, oldb); c = add(c, oldc);
			d = add(d, oldd); e = add(e, olde);
		}
		return [a, b, c, d, e];
	}
	private static function kt(t:Number):Number 
	{
		return (t < 20) ? 1518500249 : (t < 40) ? 1859775393 : (t < 60) ? -1894007588 : -899497514;
	}
	private static function ft(t:Number, b:Number, c:Number, d:Number):Number 
	{
		if (t < 20) return (b & c) | ((~b) & d);
		if (t < 40) return b ^ c ^ d;
		if (t < 60) return (b & c) | (b & d) | (c & d);
		return b ^ c ^ d;
	}
	private static function rol(n:Number, c:Number):Number 
	{
		return (n << c) | (n >>> (32 - c));
	}
	private static function add(x:Number, y:Number):Number
	{
		return UTIL.add(x, y);
	}
	
}
