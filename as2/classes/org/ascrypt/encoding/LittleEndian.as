/**
* Converts bytes and text in UTF-16 LE encoding.
* @author Mika Palmu
*/
class org.ascrypt.encoding.LittleEndian
{
	/**
	* Converts text to an array of bytes.
	* @param text An ASCII or UTF-8 encoded string.
	* @return An array of UTF-16 LE bytes.
	*/
	public static function textToBytes(text:String):Array
	{
		var b:Array = [];
		var l:Number = text.length * 2;
		for (var i:Number = 0; i < l; i += 2)
		{
			b[i] = text.charCodeAt(i / 2) & 0xFF;
			b[i + 1] = (text.charCodeAt(i / 2) >>> 8) & 0xFF;
		}
		return b;
	}
	
	/**
	* Converts an array of bytes to text.
	* @param bytes An array of UTF-16 LE bytes.
	* @return An UTF-16 LE encoded string.
	*/
	public static function bytesToText(bytes:Array):String
	{
		var l:Number = bytes.length;
		var c:Number, s:String = new String("");
		for (var i:Number = 0; i < l; i += 2)
		{
			c = (bytes[i] & 0xFF) | (bytes[i + 1] << 8);
			s += String.fromCharCode(c);
		}
		return s;
	}
	
}
