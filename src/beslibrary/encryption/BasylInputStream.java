package beslibrary.encryption;

import java.io.IOException;
import java.io.InputStream;

public class BasylInputStream extends InputStream
{
	private IBasylKeyGenerator gen;
	private InputStream in;
	
	/**
	 * Allows you to read encrypted files.
	 * @param stream
	 * @param gen
	 */
	public BasylInputStream(InputStream stream, IBasylKeyGenerator gen)
	{
		this.gen = gen;
		this.in = stream;
	}
	
	/**
	 * 
	 * @param stream
	 * @param pass
	 * @param initial
	 * @param rounds
	 * @param leftoff
	 * @param expand
	 * @param additional
	 * @param ba
	 * @return
	 * @throws IOException
	 */
	public static BasylKeyGenerator ReadFromStream(InputStream stream, String pass, int initial, int rounds, int leftoff, int expand, String additional, BasylPseudoAdaptor ba) throws IOException
	{
		byte[] sha = new byte[32];
		byte[] k2 = new byte[4];
		byte[] k1 = new byte[4];
		
		stream.read(sha);
		stream.read(k2);
		stream.read(k1);
		
		return new BasylKeyGenerator(pass, initial, rounds, leftoff, expand, additional, sha, k1, k2, true, ba);
	}
	
	
	@Override
	/**
	 * Returns byte if one exists or -1.
	 */
	public int read() throws IOException 
	{
		byte[] arr = new byte[1];
		int result = read(arr);
		if(result != -1)
		return arr[0];
		return -1;
	}
	
	
	/**
	 * Reads into the byte array
	 * @param bytes 
	 */
	public int read(byte[] bytes) throws IOException
	{
		return read(bytes, 0, bytes.length);
	}
	
	
	/**
	 * @param bytes Array to write into.
	 * @param offset Offset from start of Buffer
	 * @param length Amount to overwrite
	 */
	public int read(byte[] bytes, int offset, int length) throws IOException
	{
		int result = in.read(bytes, offset, length);
		
		for(int i =offset; i < length; i++)
		{
			bytes[i] = gen.DecryptByte(bytes[i]);
		}
		
		return result;
	}

}
