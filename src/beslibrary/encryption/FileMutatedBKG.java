package beslibrary.encryption;

import java.io.IOException;
import java.io.InputStream;

public class FileMutatedBKG extends IBasylKeyGenerator {

	
	   private BESCipher cipher;
       private IBasylKeyGenerator generator;
       private PseudoRandomGenerator prg;

       public FileMutatedBKG(IBasylKeyGenerator keyGen, InputStream stream) throws IOException
       {
           this.generator = keyGen;
           this.cipher = new BESCipher(keyGen);


           byte[] extra = new byte[100];
           byte[] extra2 = new byte[64];

           int amount = 65536;
           while (amount != 0)
           {
               byte[] buffer = new byte[amount];
               while (amount < stream.available())
               {
                   stream.read(buffer, 0, amount);
                   cipher.EncryptRight(buffer);
                   cipher.EncryptLeft(extra);
                   cipher.EncryptRight(extra2);
               }
               cipher.EncryptLeft(extra2);
               cipher.Shuffle(2);
               amount /= 2;
           }

           prg = new PseudoRandomGenerator(256 * 256, "MutatedBKG", 500);
           prg.ExpandKey(1);
           prg.SetSeedKey(extra);
           prg.SetSHA(extra2);
           prg.Recycle();
       
           stream.close();
       }
	
	@Override
	public byte GetRandomByte() {
		 byte r = generator.GetRandomByte();
         r ^= prg.GetRandomByte();
         r = cipher.EncryptLeft(r); 
         return r;
	}

	@Override
	public byte EncryptByte(byte x) {
		return (byte)(x ^ GetRandomByte());
	}

	@Override
	public void Drop() {
		// TODO Auto-generated method stub
		generator.Drop();
		prg.Drop();
	}

}
