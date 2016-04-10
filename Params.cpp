#include "Params.h"

/*
default values
*/
ZZ Params::gamma(0); 
ZZ Params::eta(0);
ZZ Params::ro(0);
ZZ Params::tau(0);
ZZ Params::ro_prim(0);


void Params::set_params(ZZ g, ZZ e, ZZ r, ZZ t, ZZ rp)
{
	gamma = g;
	eta = e;
	ro = r;
	tau = t;
	ro_prim = rp;
}
