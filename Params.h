#pragma once
#include <NTL\ZZ.h>
using namespace NTL;

class Params
{
	/*
	the bit length of the integers in the public key
	*/
	static ZZ gamma; 

	/*
	the bit length of the secret key
	*/
	static ZZ eta;

	/*
	the bit length of the noise
	*/
	static ZZ ro;
	static ZZ ro_prim;

	/*
	the integer number from public key
	*/
	static ZZ tau;

public:
	/*
	if this method is not called, the parameters take default values
	*/
	static void set_params(ZZ gamma, ZZ eta, ZZ ro, ZZ tau, ZZ ro_prim);

	static ZZ getGamma()
	{
		return gamma;
	}

	static ZZ getEta()
	{
		return eta;
	}

	static ZZ getRo()
	{
		return ro;
	}

	static ZZ getRoPrim()
	{
		return ro_prim;
	}

	static ZZ getTau()
	{
		return tau;
	}
};

