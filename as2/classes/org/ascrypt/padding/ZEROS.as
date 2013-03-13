/**
* Pads and unpads data with zero padding scheme.
* @author Mika Palmu
*/
class org.ascrypt.padding.ZEROS
{
	/**
	* Pads bytes with zero padding scheme.
	* @param bytes An array of unpadded bytes.
	* @param size The block size to pad to.
	* @return An array of padded bytes.
	*/
	public static function pad(bytes:Array, size:Number):Array
	{
		var c:Array = bytes.concat();
		while (c.length % size != 0) c[c.length] = 0;
		return c;
	}
	
	/**
	* Unpads bytes with zero padding scheme.
	* @param bytes An array of padded bytes.
	* @return An array of unpadded bytes.
	*/
	public static function unpad(bytes:Array):Array
	{
		var c:Array = bytes.concat();
		while (c[c.length - 1] == 0) c.pop();
		return c;
	}
	
}
