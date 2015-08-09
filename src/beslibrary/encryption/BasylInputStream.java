package beslibrary.encryption;

import java.io.IOException;
import java.io.InputStream;

public class BasylInputStream extends InputStream
{
	private IBasylKeyGenerator gen;
	private InputStream in;
	
	public BasylInputStream(InputStream stream, IBasylKeyGenerator gen)
	{
		this.gen = gen;
		this.in = stream;
	}
	
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
	public int read() throws IOException 
	{
		byte[] arr = new byte[1];
		int result = read(arr);
		if(result != -1)
		return arr[0];
		return -1;
	}
	
	
	public int read(byte[] bytes) throws IOException
	{
		return read(bytes, 0, bytes.length);
	}
	
	
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
