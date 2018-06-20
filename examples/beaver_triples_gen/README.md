# Beaver triple generation

Simple example of how to generate a beaver triple for two-party secure computation on arithmetic circuits.
It uses Gillboa's algorithm to multiply two random values via oblivious transfer twice (one in each direction)
and sums them up so each pariticipant holds a share of a, b, c with a * b = c 
[Gilboa "Two Party RSA Key Generation", Keller et al. "MASCOT: Faster Malicious Arithmetic Secure Computation with Oblivious Transfer" TODO: make this correct,]

These then can be used to multiply shares via beaver's method.