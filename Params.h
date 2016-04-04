#pragma once
class Params
{
	/*
	the bit length of the integers in the public key
	*/
	static int gamma; 

	/*
	the bit length of the secret key
	*/
	static int eta;

	/*
	the bit length of the noise
	*/
	static int ro;
	static int ro_prim;

	/*
	the integer number from public key
	*/
	static int tau;

public:
	/*
	if this method is not called, the parameters take default values
	*/
	static void set_params(int gamma, int eta, int ro, int tau, int ro_prim = 0);

	static int getGamma()
	{
		return gamma;
	}

	static int getEta()
	{
		return eta;
	}

	static int getRo()
	{
		return ro;
	}

	static int getRoPrim()
	{
		return ro_prim;
	}

	static int getTau()
	{
		return tau;
	}
};

