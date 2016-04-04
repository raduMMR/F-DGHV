#include "Params.h"

/*
default values
*/
int Params::gamma = 0;
int Params::eta = 0;
int Params::ro = 0;
int Params::tau = 0;
int Params::ro_prim = 0;


void Params::set_params(int g, int e, int r, int t, int rp)
{
	gamma = g;
	eta = e;
	ro = r;
	tau = t;
	ro_prim = rp;
}
