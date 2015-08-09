package beslibrary.encryption;

import java.security.SecureRandom;

public abstract class IBasylKeyGenerator 
{
	private static SecureRandom random = new SecureRandom();
	
	
	public void FillBytes(byte[] arr, int offset, int count)
	{
		for (int i = 0; i < count; i++)
	    {
	        arr[offset + i] = GetRandomByte();
	    }
			
	}
	
	public void FillBytes(byte[] arr)
	{
		FillBytes(arr, 0, arr.length);
	}
	
	
	public abstract byte GetRandomByte();
	public abstract byte EncryptByte(byte x);
	public byte DecryptByte(byte x)
	{
		return EncryptByte(x);
	}
	
	public abstract void Drop();
	
	public static byte[] GenerateRandomHash()
	{
		byte[] arr = new byte[32];
		random.nextBytes(arr);
		return arr;
	}
	
}
