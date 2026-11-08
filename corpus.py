"""English sample text used for plaintexts and for the frequency tables."""
import re
TEXT = """
It was a bright cold day in the middle of the spring and the clocks in the old harbour town were striking noon.
The merchants opened their shutters and the fishermen carried their baskets up from the quay while the gulls
circled over the market square. A young clerk hurried along the street with a bundle of letters under his arm,
for the ship from the south had arrived early and every office in the town wanted its news at once. Nobody had
expected the storm to pass so quickly, and nobody had expected the cargo to be so large. There were crates of
tea and spices, barrels of oil and wine, and long boxes of books that the university had ordered the previous year.
The harbour master read the manifest twice and then signed it with a sigh, because he knew that the next week
would be full of work. In the evening the people gathered in the tavern near the water to talk about the voyage,
the price of grain, the new tax on salt, and the rumour that a railway would soon be built across the hills.
The older men argued that the railway would ruin the town, while the younger men said it would make everyone rich.
A teacher who had been listening quietly in the corner finally stood up and said that nobody could know the future,
but that a town which learned to read, to count and to build would never be afraid of change. The room fell silent
for a moment and then the innkeeper laughed and filled every glass. Outside the wind rose again over the sea and
the lanterns swung gently above the doors. Computers and codes, in those days, were only a dream, yet the clerks
already knew how to hide a message from curious eyes by shifting letters and shuffling words according to a secret
rule that only the sender and the receiver understood. Such rules are simple to state and difficult to guess, and
the best of them depend not on the cleverness of the method but on the secrecy and the length of the key.
Every cipher has a weakness, and the patient observer who counts the letters, compares the patterns and tests
each small guess will usually find a way in before the winter is over.
"""
PLAIN = re.sub(r"[^A-Z]", "", TEXT.upper())

# standard English letter frequencies (%), A..Z
ENGLISH_FREQ = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406,
                6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074]
