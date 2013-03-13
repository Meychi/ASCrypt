import org.ascrypt.utilities.*;

/**
* Computes a RIPEMD-160 checksum for the specified data.
* <br/><br/>RIPEMD-160 is a cryptographic hash function that computes a message digest of 160 bits.
* @author Mika Palmu
*/
class org.ascrypt.RMD160
{
	/**
	* Private properties is the class.
	*/
	private static var r1:Array = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
	private static var r2:Array = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
	private static var s1:Array = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
	private static var s2:Array = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];	
	
	/**
	* Computes a RIPEMD-160 checksum for the bytes.
	* @param bytes An array of bytes in any encoding.
	* @return An array of RIPEMD-160 computed bytes.
	*/
	public static function compute(bytes:Array):Array
	{
		var b:Array = UTIL.pack(bytes);
		return UTIL.unpack(core(b, bytes.length * 8));
	}
	
	/**
	* Computes a HMAC-RIPEMD-160 for the key and bytes.
	* @param key An array of bytes in any encoding.
	* @param bytes An array of bytes in any encoding.
	* @return An array of HMAC-RIPEMD-160 computed bytes.
	*/
	public static function computeHMAC(key:Array, bytes:Array):Array
	{
		return HMAC.compute(key, bytes, RMD160.compute, 64);
	}
	
	/**
	* Private methods of the class.
	*/
	private static function core(x:Array, l:Number):Array
	{
		x[l >> 5] |= 0x80 << (l % 32);
		x[(((l + 64) >>> 9) << 4) + 14] = l;
		var h0:Number = 0x67452301, h1:Number = 0xefcdab89;
		var h2:Number = 0x98badcfe, h3:Number = 0x10325476, h4:Number = 0xc3d2e1f0;
		for (var i:Number = 0; i < x.length; i += 16) 
		{
			var t:Number, a1:Number = h0, b1:Number = h1, c1:Number = h2;
			var d1:Number = h3, e1:Number = h4, a2:Number = h0, b2:Number = h1;
			var c2:Number = h2, d2:Number = h3, e2:Number = h4;
			for (var j:Number = 0; j <= 79; ++j) 
			{
				t = add(a1, f(j, b1, c1, d1));
				t = add(t, x[i + r1[j]]);
				t = add(t, k1(j));
				t = add(rol(t, s1[j]), e1);
				a1 = e1; e1 = d1; 
				d1 = rol(c1, 10); 
				c1 = b1; b1 = t;
				t = add(a2, f(79 - j, b2, c2, d2));
				t = add(t, x[i + r2[j]]);
				t = add(t, k2(j));
				t = add(rol(t, s2[j]), e2);
				a2 = e2; e2 = d2; 
				d2 = rol(c2, 10); 
				c2 = b2; b2 = t;
			}
			t = add(h1, add(c1, d2));
			h1 = add(h2, add(d1, e2));
			h2 = add(h3, add(e1, a2));
			h3 = add(h4, add(a1, b2));
			h4 = add(h0, add(b1, c2));
			h0 = t;
		}
		return [h0, h1, h2, h3, h4];
	}
	private static function f(j:Number, x:Number, y:Number, z:Number):Number
	{
		return (0 <= j && j <= 15) ? (x ^ y ^ z) :(16 <= j && j <= 31) ? (x & y) | (~x & z) : (32 <= j && j <= 47) ? (x | ~y) ^ z : (48 <= j && j <= 63) ? (x & z) | (y & ~z) : (64 <= j && j <= 79) ? x ^ (y | ~z) : Infinity;
	}
	private static function k1(j:Number):Number
	{
		return (0 <= j && j <= 15) ? 0x00000000 : (16 <= j && j <= 31) ? 0x5a827999 : (32 <= j && j <= 47) ? 0x6ed9eba1 : (48 <= j && j <= 63) ? 0x8f1bbcdc : (64 <= j && j <= 79) ? 0xa953fd4e : Infinity;
	}
	private static function k2(j:Number):Number
	{
		return (0 <= j && j <= 15) ? 0x50a28be6 : (16 <= j && j <= 31) ? 0x5c4dd124 : (32 <= j && j <= 47) ? 0x6d703ef3 : (48 <= j && j <= 63) ? 0x7a6d76e9 : (64 <= j && j <= 79) ? 0x00000000 : Infinity;
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
