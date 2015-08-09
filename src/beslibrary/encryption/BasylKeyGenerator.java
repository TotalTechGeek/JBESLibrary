package beslibrary.encryption;

import java.security.SecureRandom;

public class BasylKeyGenerator extends IBasylKeyGenerator 
{


    private PseudoRandomGenerator Key1;
    private PseudoRandomGenerator Key2;
	

    private byte[] Key1Random, Key2Random;
    private byte[] sha;


    
	//Default Settings
    public static final int INITIAL = 131072;
    public static final int ROUNDS = 200;
    public static final int LEFTOFF = 1200;
    public static final int EXPANSION = 120;
    public static final String ADDITIONALKEY = "ABCD";
    //End Default Settings
	
    /// <summary>
    /// Generates a Key Generator from the password.
    /// </summary>
    /// <param name="pass"></param>
    public BasylKeyGenerator(String pass) 
    {
    	this(pass, INITIAL, ROUNDS, LEFTOFF, EXPANSION, ADDITIONALKEY, GenerateRandomHash());
    }
	
	
 // <summary>
    /// This creates a Basyl Key Generator from the arguments..
    /// </summary>
    /// <param name="pass"></param>
    /// <param name="initial"></param>
    /// <param name="rounds"></param>
    /// <param name="leftoff"></param>
    /// <param name="expansion"></param>
    /// <param name="additionalKey"></param>
    /// <param name="sha"></param>
    /// <param name="Key1Random"></param>
    /// <param name="Key2Random"></param>
    /// <param name="encryptedKey1"></param>
    public BasylKeyGenerator(String pass, int initial, int rounds, int leftoff, int expansion, String additionalKey, byte[] sha, byte[] Key1Random, byte[] Key2Random, boolean encryptedKey1)  
    {
    	this(pass, initial, rounds, leftoff, expansion, additionalKey, sha, Key1Random, Key2Random, encryptedKey1, null);
    }
    
    /// <summary>
    /// This creates a Basyl Key Generator from the arguments..
    /// </summary>
    /// <param name="pass"></param>
    /// <param name="initial"></param>
    /// <param name="rounds"></param>
    /// <param name="leftoff"></param>
    /// <param name="expansion"></param>
    /// <param name="additionalKey"></param>
    /// <param name="sha"></param>
    /// <param name="Key1Random"></param>
    /// <param name="Key2Random"></param>
    /// <param name="encryptedKey1"></param>
    /// <param name="adaptor"></param>
    public BasylKeyGenerator(String pass, int initial, int rounds, int leftoff, int expansion, String additionalKey, byte[] sha, byte[] Key1Random, byte[] Key2Random, boolean encryptedKey1, BasylPseudoAdaptor adaptor)
    {
        if (adaptor == null) adaptor = new BasylPseudoAdaptor();
        this.sha = sha;
        this.Key2Random = Key2Random;
        
        PseudoRandomGenerator Key1 = new PseudoRandomGenerator(initial, pass, rounds, adaptor);
        Key2 = new PseudoRandomGenerator(1024 * 40, pass, 400, adaptor);

        //Set the left off
        Key1.SetLeftoff(leftoff);
        Key2.SetLeftoff(80);

        //Set String Recycle Key
        Key1.SetRecycleKey(additionalKey);
        Key2.SetRecycleKey(additionalKey);

        //Expand the Keys
        Key1.ExpandKey(expansion);
        Key2.ExpandKey(5);

        //Set SHA
        Key1.SetSHA(sha);
        Key2.SetSHA(sha);


        //Add randomness.
        Key2.SetSeedKey(Key2Random);


        //Recycle Key 2
        Key2.Recycle();

        //Stop Recycling Key 2
        //Key2.StopRecycling();


        //Add Key 1 Randomness

        if(encryptedKey1)
        for (int i = 0; i < Key1Random.length; i++)
        {
            Key1Random[i] ^= Key2.GetRandomByte();
        }
       
        this.Key1Random = Key1Random;
        Key1.SetSeedKey(Key1Random);

        //Recycle Key 1
        Key1.Recycle();

        //this.Key1 = new FilePseudoRandomGenerator(File.Open("Key1", FileMode.Create), Key1, additionalKey, Key1Random, sha, leftoff);
        this.Key1 = Key1;

    }
    
    /// <summary>
    /// This is mainly used by the Basyl Writer.
    /// Creates a Basyl Key Generator from the arguments.
    /// </summary>
    /// <param name="pass"></param>
    /// <param name="initial"></param>
    /// <param name="rounds"></param>
    /// <param name="leftoff"></param>
    /// <param name="expansion"></param>
    /// <param name="additionalKey"></param>
    /// <param name="sha"></param>
    public BasylKeyGenerator(String pass, int initial, int rounds, int leftoff, int expansion, String additionalKey, byte[] sha) 
    {
    	 this(pass, initial, rounds, leftoff, expansion, additionalKey, sha, null);
    }
    
    /// <summary>
    /// 
    /// </summary>
    /// <param name="pass"></param>
    /// <param name="initial"></param>
    /// <param name="rounds"></param>
    /// <param name="leftoff"></param>
    /// <param name="expansion"></param>
    /// <param name="additionalKey"></param>
    public BasylKeyGenerator(String pass, int initial, int rounds, int leftoff, int expansion, String additionalKey)
    {
    	 this(pass, initial, rounds, leftoff, expansion, additionalKey, GenerateRandomHash(), null);
    }
    
    

    /// <summary>
    /// This is mainly used by the Basyl Writer.
    /// Creates a Basyl Key Generator from the arguments.
    /// </summary>
    /// <param name="pass"></param>
    /// <param name="initial"></param>
    /// <param name="rounds"></param>
    /// <param name="leftoff"></param>
    /// <param name="expansion"></param>
    /// <param name="additionalKey"></param>
    /// <param name="sha"></param>
    ///<param name="adaptor"></param>
    public BasylKeyGenerator(String pass, int initial, int rounds, int leftoff, int expansion, String additionalKey, byte[] sha, BasylPseudoAdaptor adaptor)
    {
        if (adaptor == null) adaptor = new BasylPseudoAdaptor();
        SecureRandom random = new SecureRandom();

        PseudoRandomGenerator Key1 = new PseudoRandomGenerator(initial, pass, rounds, adaptor);
        Key2 = new PseudoRandomGenerator(1024 * 40, pass, 400, adaptor);

        Key1Random = new byte[4];
        Key2Random = new byte[4];

        //Set the left off
        Key1.SetLeftoff(leftoff);
        Key2.SetLeftoff(80);


        //Set String Recycle Key
        Key1.SetRecycleKey(additionalKey);
        Key2.SetRecycleKey(additionalKey);

        //Expand the Keys
        Key1.ExpandKey(expansion);
        Key2.ExpandKey(5);


        //Generate Randomness
        random.nextBytes(Key1Random);
        random.nextBytes(Key2Random);

        //Add randomness.
        Key1.SetSeedKey(Key1Random);
        Key2.SetSeedKey(Key2Random);

        //if sha exists
        if (sha != null)
        {
            this.sha = sha;
            //Set SHA
            Key1.SetSHA(sha);
            Key2.SetSHA(sha);
        }

        //Recycle the Keys
        Key1.Recycle();
        Key2.Recycle();

        //this.Key1 = new FilePseudoRandomGenerator(File.Open("Key1", FileMode.Create), Key1, additionalKey, Key1Random, sha, leftoff);
        this.Key1 = Key1;


    }
    
    /// <summary>
    /// Get Encrypted Key 1.
    /// Only works first time.
    /// </summary>
    /// <returns></returns>
    public byte[] GetEncryptedKey1Random()
    {
        byte[] a = (byte[])Key1Random.clone();

        for(int i = 0; i < a.length; i++)
        {
            a[i] ^= Key2.GetRandomByte();
        }

        return a;
    }
    
    
    /// <summary>
    /// Gets the randomizer seed of the first key.
    /// </summary>
    /// <returns></returns>
    public byte[] GetFirstRandomizer()
    {
        return Key1Random;
    }


    /// <summary>
    /// Gets the SHA used.
    /// </summary>
    /// <returns></returns>
    public byte[] GetSHA()
    {
        return sha;
    }

    /// <summary>
    /// Gets the randomizer seed of the second key.
    /// </summary>
    /// <returns></returns>
    public byte[] GetSecondRandomizer()
    {
        return Key2Random;
    }

    

    /// <summary>
    /// Forces the Writer to recycle the keys.
    /// </summary>
    public void ForceRecycle()
    {
        Key1.Recycle();
        Key2.Recycle();
    }
    

    /// <summary>
    /// Sets the SHA seed used by the writer.
    /// </summary>
    /// <param name="sha"></param>
    public void SetSHA(byte[] sha)
    {
        Key1.SetSHA(sha);
        Key2.SetSHA(sha);
        this.sha = sha;
    }

    /// <summary>
    /// Sets a Recycle Key used by the Writer.
    /// </summary>
    /// <param name="r"></param>
    public void SetRecycleKey(String r)
    {
        Key1.SetRecycleKey(r);
        Key2.SetRecycleKey(r);
    }


    
    
	@Override
	public byte GetRandomByte() {
		// TODO Auto-generated method stub
		return (byte)(Key1.GetRandomByte() ^ Key2.GetRandomByte());
	}

	@Override
	public byte EncryptByte(byte x) {
		// TODO Auto-generated method stub
		return (byte)(x ^ GetRandomByte());
	}

	@Override
	public void Drop() {
		// TODO Auto-generated method stub
		Key1.Drop();
        Key2.Drop();
	}

}
