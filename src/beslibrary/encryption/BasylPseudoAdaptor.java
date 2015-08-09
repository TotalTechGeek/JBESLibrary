package beslibrary.encryption;

import java.util.ArrayList;

public class BasylPseudoAdaptor {
	/// <summary>
    /// This is a swap that can be overridden for different behaviour.
    /// It doesn't necessarily need to swap in this step.
    /// Default behaviour just swaps them.
    /// </summary>
    /// <param name="b1"></param>
    /// <param name="b2"></param>
    public void OddSwap(ArrayList<Long> x, int pos1, int pos2)
    {
        Long temp = x.get(pos1);
        x.set(pos1, x.get(pos2));
        x.set(pos2, temp);
    }

    /// <summary>
    /// Doesn't necessarily have to do anything. You could leave it empty. This just adds an extra step 
    /// in the generation scheme. By default it is empty.
    /// </summary>
    /// <param name="x">What will be passed in by the PRNG to Shuffle.</param>
    /// <param name="round">What round it is.</param>
    public void Shuffle(ArrayList<Long> x, int round)
    {
    }

    /// <summary>
    /// What is called when recycling.
    /// </summary>
    /// <param name="x"></param>
    public void Recycle(ArrayList<Long> x)
    {
    }

    /// <summary>
    /// Used to seed the generation array.
    /// Should be changed out for various programs.
    /// </summary>
    /// <param name="pos"></param>
    /// <param name="seed"></param>
    /// <returns></returns>
    public Long SeedFunction(Long pos, Long seed)
    {
        return  pos * pos + 2 * pos + pos * pos * pos + seed * pos + seed;
    }

}
