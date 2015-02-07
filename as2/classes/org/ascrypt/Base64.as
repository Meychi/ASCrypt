/**
* Encodes and decodes data with base64 encoding.
* <br/><br/>Base64 is a MIME content transfer encoding that only uses characters A-Z, a-z, and 0-9.
* @author Mika Palmu
*/
class org.ascrypt.Base64 
{
	/**
	* Characters used in the base64 calculation.
	*/
	private static var chrs:String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	
	/**
	* Encodes bytes to a base64 string.
	* @param bytes An array of ASCII or UTF-8 bytes.
	* @return The encoded base64 string.
	*/
	public static function encode(bytes:Array):String
	{
		var l:Number = bytes.length;
		var c1:Number, c2:Number, c3:Number;
		var e1:Number, e2:Number, e3:Number, e4:Number;
		var i:Number = 0, t:String = new String("");
		while (i < l) 
		{
			c1 = bytes[i++];
			c2 = bytes[i++];
			c3 = bytes[i++];
			e1 = c1 >> 2;
			e2 = ((c1 & 3) << 4) | (c2 >> 4);
			e3 = ((c2 & 15) << 2) | (c3 >> 6);
			e4 = c3 & 63;
			t += chrs.charAt(e1) + chrs.charAt(e2);
			if (i <= l) t += chrs.charAt(e3);
			if (i <= l) t += chrs.charAt(e4);
		}
		if (isNaN(c2)) t += "=";
		if (isNaN(c3)) t += "=";
		return t;
	}
	
	/**
	* Decodes base64 string to bytes.
	* @param text The encoded base64 string.
	* @return An array of decoded bytes.
	*/
	public static function decode(text:String):Array
	{
		var l:Number = text.length;
		var i:Number = 0, b:Array = [];
		var c1:Number, c2:Number, c3:Number;
		var e1:Number, e2:Number, e3:Number, e4:Number;
		while (i < l) 
		{
			e1 = chrs.indexOf(text.charAt(i++));
			e2 = chrs.indexOf(text.charAt(i++));
			e3 = chrs.indexOf(text.charAt(i++));
			e4 = chrs.indexOf(text.charAt(i++));
			c1 = (e1 << 2) | (e2 >> 4);
			c2 = ((e2 & 15) << 4) | (e3 >> 2);
			c3 = ((e3 & 3) << 6) | e4;
			b.push(c1);
			if (e3 != 64) b.push(c2);
			if (e4 != 64) b.push(c3);
		}
		return b;
	}
	
}
