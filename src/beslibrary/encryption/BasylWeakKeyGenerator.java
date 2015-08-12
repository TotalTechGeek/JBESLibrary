package beslibrary.encryption;

public class BasylWeakKeyGenerator extends IBasylKeyGenerator
{
	
	private PseudoRandomGenerator prng;
	
	public BasylWeakKeyGenerator(PseudoRandomGenerator prng)
	{
		this.prng = prng;
	}
	
	
	public PseudoRandomGenerator GetPseudoRandomGenerator()
	{
		return prng;
	}

	@Override
	public byte GetRandomByte() {
		// TODO Auto-generated method stub
		return prng.GetRandomByte();
	}

	@Override
	public byte EncryptByte(byte x) {
		// TODO Auto-generated method stub
		return (byte)(GetRandomByte() ^ x);
	}

	@Override
	public void Drop() {
		// TODO Auto-generated method stub
		prng.Drop();
	}

}
