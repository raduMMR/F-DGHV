#pragma once
// #include <NTL\ZZ.h>
// using namespace NTL;

typedef unsigned long UL;

class Params
{
	/*
	the bit length of the integers in the public key
	*/
	static UL gamma; 

	/*
	the bit length of the secret key
	*/
	static UL eta;

	/*
	the bit length of the noise
	*/
	static UL ro;
	static UL ro_prim;

	/*
	the integer number from public key
	*/
	static UL tau;

public:
	/*
	if this method is not called, the parameters take default values
	*/
	static void set_params(UL gamma, UL eta,
		UL ro, UL tau, UL ro_prim);

	static UL getGamma()
	{
		return gamma;
	}

	static UL getEta()
	{
		return eta;
	}

	static UL getRo()
	{
		return ro;
	}

	static UL getRoPrim()
	{
		return ro_prim;
	}

	static UL getTau()
	{
		return tau;
	}
};

