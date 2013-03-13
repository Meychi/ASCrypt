import org.ascrypt.utilities.*;

/**
* Computes a SHA-256 checksum for the specified data.
* <br/><br/>SHA-256 is a cryptographic hash function that computes a message digest of 256 bits.
* @author Mika Palmu
*/
class org.ascrypt.SHA256
{
	/**
	* Computes a SHA-256 checksum for the bytes.
	* @param bytes An array of bytes in any encoding.
	* @return An array of SHA-256 computed bytes.
	*/
	public static function compute(bytes:Array):Array
	{
		var b:Array = UTIL.pack(bytes, false);
		return UTIL.unpack(core(b, bytes.length * 8), false);
	}
	
	/**
	* Computes a HMAC-SHA-256 for the key and bytes.
	* @param key An array of bytes in any encoding.
	* @param bytes An array of bytes in any encoding.
	* @return An array of HMAC-SHA-256 hashed bytes.
	*/
	public static function computeHMAC(key:Array, bytes:Array):Array
	{
		return HMAC.compute(key, bytes, SHA256.compute, 64);
	}
	
	/**
	* Private methods of the class.
	*/
	private static function core(m:Array, l:Number):Array
	{
		var a:Number, b:Number, c:Number, d:Number; 
		var e:Number, f:Number, g:Number, h:Number;
		var t1:Number, t2:Number, w:Array = new Array(64);
		var k:Array = [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2];
		var r:Array = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];
		m[l >> 5] |= 0x80 << (24 - l % 32);
		m[((l + 64 >> 9) << 4) + 15] = l;
		for (var i:Number = 0; i < m.length; i += 16)
		{
			a = r[0]; b = r[1]; c = r[2]; d = r[3];
			e = r[4]; f = r[5]; g = r[6]; h = r[7];
			for (var j:Number = 0; j < 64; j++)
			{
				if (j < 16) w[j] = m[j + i];
				else w[j] = add(add(add(g1256(w[j - 2]), w[j - 7]), g0256(w[j - 15])), w[j - 16]);
				t1 = add(add(add(add(h, s1256(e)), ch(e, f, g)), k[j]), w[j]);
				t2 = add(s0256(a), maj(a, b, c));
				h = g; g = f; f = e; e = add(d, t1);
				d = c; c = b; b = a; a = add(t1, t2);
			}
			r[0] = add(a, r[0]); r[1] = add(b, r[1]);
			r[2] = add(c, r[2]); r[3] = add(d, r[3]);
			r[4] = add(e, r[4]); r[5] = add(f, r[5]);
			r[6] = add(g, r[6]); r[7] = add(h, r[7]);
		}
		return r;
	}
	private static function s(x:Number, n:Number):Number 
	{
		return (x >>> n) | (x << (32 - n));
	}
	private static function ch(x:Number, y:Number, z:Number):Number 
	{
		return ((x & y) ^ ((~x) & z));
	}
	private static function maj(x:Number, y:Number, z:Number):Number 
	{
		return ((x & y) ^ (x & z) ^ (y & z));
	}
	private static function s0256(x:Number):Number 
	{
		return (s(x, 2) ^ s(x, 13) ^ s(x, 22));
	}
	private static function s1256(x:Number):Number 
	{
		return (s(x, 6) ^ s(x, 11) ^ s(x, 25));
	}
	private static function g0256(x:Number):Number 
	{
		return (s(x, 7) ^ s(x, 18) ^ (x >>> 3));
	}
	private static function g1256(x:Number):Number 
	{
		return (s(x, 17) ^ s(x, 19) ^ (x >>> 10));
	}
	private static function add(x:Number, y:Number):Number
	{
		return UTIL.add(x, y);
	}
	
}
