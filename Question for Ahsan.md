What's the rationale for having two pairs of functions for converting between bytes to nibbles?

Just to make my life easier, I'd like to pick a pair and delete the other. 

At first glance, the pair on the left makes more sense to me, in that FromNibbleByte turns a (singular) byte into a singular nibble (NibbleFromByte does some weird bitwise arithmetic stuff and turns a single byte into a slice of two nibbles, why?)

But if you inspect the source code, the second pair is more often used than the first pair, by a significant margin.

Any idea why the NibblesFromByte (from the second pair) does what it does?