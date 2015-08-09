package beslibrary.encryption;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;

/**
 * This is used to output data to another stream after
 * encrypting it via key generator.
 * @author Jesse
 *
 */
public class BasylOutputStream extends OutputStream
{
	private OutputStream stream;
	private IBasylKeyGenerator gen;
	
	public BasylOutputStream(OutputStream stream, IBasylKeyGenerator gen, boolean export)
	{
		this.gen = gen;
		this.stream = stream;
		if(export)
		{
			if(gen instanceof BasylKeyGenerator)
			{
				BasylKeyGenerator g=  (BasylKeyGenerator)gen;
				byte[] k1r = ((BasylKeyGenerator) gen).GetEncryptedKey1Random();
				byte[] k2 = ((BasylKeyGenerator) gen).GetSecondRandomizer();
				byte[] sha = ((BasylKeyGenerator) gen).GetSHA();
				
				try 
				{
					stream.write(sha);
					stream.write(k2);
					stream.write(k1r);
				} catch (IOException e) 
				{
					e.printStackTrace();
				}
			}
			
		}
	}
	
	
	@Override
	public void write(int arg0) throws IOException
	{
		write(new byte[]{ (byte)arg0 });
	}
	
	public void write(byte[] bytes) throws IOException
	{
		
	     write(bytes, 0, bytes.length);
	}
	
	public void write(String str) throws IOException
	{
		byte[] b = str.getBytes(Charset.forName("UTF-8"));
		write(b.length);
		write(b);
	}
	
	public void write(byte[] bytes, int offset, int length) throws IOException
	{
		 byte[] arr = bytes.clone();
		 for(int i = offset; i < length; i++)
		 arr[i] = gen.EncryptByte(bytes[i]);
		
	     stream.write(arr, offset, length);
	}
	
	
	public void close() throws IOException
	{
		stream.close();
	}
}
