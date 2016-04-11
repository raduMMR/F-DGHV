#include "Flat_DGHV.h"
#include "Params.h"
#include "utilities.h"
#include <assert.h>

Flat_DGHV::Flat_DGHV(int lambda)
{
	compute_DGHV_settings(lambda);
	compute_FDGHV_settings();
}

Flat_DGHV::Flat_DGHV(char *filename)
{
	UL params[6];

	read_DGHV_params_from_file(filename, params, pk_DGHV, sk_DGHV);

	// Params::set_params(gamma, eta, ro, tau, ro_prim);
	Params::set_params(params[1], params[2], params[3], params[4], params[5]);

	compute_FDGHV_settings();
}

Flat_DGHV::Flat_DGHV(char *filename, int lambda)
{
	// this->lambda = lambda;

	compute_DGHV_settings(filename, lambda);

	compute_FDGHV_settings();
}

void Flat_DGHV::compute_DGHV_settings(char *filename, int lambda)
{
	/*UL gamma = pow(lambda, 4);
	UL eta = lambda*lambda;
	UL ro = lambda;
	UL tau = gamma + lambda;
	UL ro_prim = 2 * lambda;

	Params::set_params(gamma, eta, ro, tau, ro_prim);

	generate_keys(sk_DGHV, pk_DGHV);
	assert(pk_DGHV.size() != 0);*/

	compute_DGHV_settings(lambda);

	UL params[6];
	params[0] = lambda;
	params[1] = Params::getGamma();
	params[2] = Params::getEta();
	params[3] = Params::getRo();
	params[4] = Params::getTau();
	params[5] = Params::getRoPrim();

	write_DGHV_params_in_file(filename, params, pk_DGHV, sk_DGHV);
}

void Flat_DGHV::compute_DGHV_settings(int lambda)
{
	UL gamma = pow(lambda, 4);
	UL eta = lambda*lambda;
	UL ro = lambda;
	UL tau = gamma + lambda;
	UL ro_prim = 2 * lambda;

	Params::set_params(gamma, eta, ro, tau, ro_prim);

	generate_keys(sk_DGHV, pk_DGHV);
	assert(pk_DGHV.size() != 0);
}

void Flat_DGHV::compute_FDGHV_settings()
{
	l = 0;					// l = log x_0 + 1
	ZZ x_0 = pk_DGHV[0];
	while (x_0 != 0)
	{
		l++;
		x_0 = x_0 / 2;
	}
	assert(l != 0);
	l += 1;

	v.reserve(l);			// v = Powersof2(1);
	ZZ two(2);
	ZZ pow_of_two(1);
	for (int i = 0; i < l; i++)
	{
		v.push_back(pow_of_two);
		pow_of_two *= 2;
	}

	C_prim.reserve(l);
	for (int i = 0; i < l; i++)
	{
		// o criptare noua pentru fiecare linie a matricii C_prim
		Vec_ZZ empty;
		C_prim.push_back(empty);

		// pentru fiecare linie avem o criptare a lui zero diferita
		C_prim[i].push_back(encrypt_DGHV(0));
	}
}

ZZ	Flat_DGHV::encrypt_DGHV(int message)const
{
	return encrypt_integer(pk_DGHV, ZZ(message));
}

int	Flat_DGHV::decrypt_DGHV(ZZ &ctxt)const
{
	return ( ctxt % sk_DGHV % 2 );
}

Vec_ZZ Flat_DGHV::bitdecomp(Vec_ZZ &C_i)const
{
	Vec_ZZ C_decomp;
	long length = C_i.size() * l;
	C_decomp.reserve(length);

	ZZ elem;
	for (int i = 0, j=-1; i < length; i++)
	{
		if (i % l == 0)
		{
			j++;
			elem = C_i[j];
		}

		C_decomp.push_back(ZZ(elem % 2));
		elem = elem / 2;
	}

	return C_decomp;
}

Vec_ZZ Flat_DGHV::bitdecomp_1(Vec_ZZ &C_i)const
{
	Vec_ZZ C_decomp_1;
	long length = C_i.size() / l;
	C_decomp_1.reserve(length);

	ZZ pow_of_two(1);
	ZZ two(2);
	for (int i = 0, j = -1; i < C_i.size(); i++)
	{
		if (i % l == 0)
		{
			pow_of_two = 1;
			j++;
			C_decomp_1.push_back(ZZ(0));		//C_decomp_1[j] = 0;
		}

		C_decomp_1[j] +=  C_i[i] * pow_of_two;
		pow_of_two *= two;
	}

	return C_decomp_1;
}

Mat_ZZ Flat_DGHV::flatten(Mat_ZZ &C)const
{
	Mat_ZZ Flat_C;
	Flat_C.reserve(l);
	Vec_ZZ bd_1;

	for (int i = 0; i < C.size(); i++)
	{
		Vec_ZZ empty;
		Flat_C.push_back(empty);

		bd_1 = bitdecomp_1(C[i]);
		C[i][0] = bd_1[0] % pk_DGHV[0];

		Flat_C[i] = bitdecomp(bd_1);
	}

	return Flat_C;
}

Mat_ZZ Flat_DGHV::encrypt(int message)const
{
	Mat_ZZ C;
	C.reserve(l);

	for (int i = 0; i < l; i++)
	{
		Vec_ZZ empty;
		C.push_back(empty);
		Vec_ZZ linie = C_prim[i];
		C[i] = bitdecomp(linie);
		C[i][i] += message;
	}
	flatten(C);

	return C;
}

int Flat_DGHV::decrypt(Mat_ZZ &C)const
{
	ZZ message(0);
	for (int i = 0; i < l; i++)
	{
		message += C[0][i] * v[i];
	}
	return decrypt_DGHV(message);
}

Mat_ZZ Flat_DGHV::hom_add(Mat_ZZ &C1, Mat_ZZ &C2)const
{
	assert(C1.size() == C2.size());
	assert(C1.size() == l);
	assert(C1[0].size() == l);

	Mat_ZZ C_add;
	C_add.reserve(l);
	
	for (int i = 0; i < l; i++)
	{
		for (int j = 0; j < l; j++)
		{
			C_add[i].push_back(C1[i][j] + C2[i][j]);
		}
	}

	return flatten(C_add);
}

Mat_ZZ Flat_DGHV::hom_mult(Mat_ZZ &C1, Mat_ZZ &C2)const
{
	assert(C1.size() == C2.size());
	assert(C1.size() == l);
	assert(C1[0].size() == l);

	Mat_ZZ C_mult;
	C_mult.reserve(l);

	ZZ z;
	for (int i = 0; i < l; i++)
	{
		Vec_ZZ empty;
		C_mult.push_back(empty);

		C_mult[i].reserve(l);
		
		for (int j = 0; j < l; j++)
		{
			C_mult[i].push_back(ZZ(0));
			for (int k = 0; k < l; k++)
			{
				C_mult[i][j] += C1[i][k] * C2[k][j];
			}
		}
	}

	return flatten(C_mult);
}

Mat_ZZ Flat_DGHV::hom_mult_opt(Mat_ZZ &C1, Mat_ZZ &C2)const
{
	assert(C1.size() == C2.size());
	assert(C1.size() == l);
	assert(C1[0].size() == l);

	Mat_ZZ C_mult;
	C_mult.reserve(l);

	Mat_ZZ C1_prim;
	C1_prim.reserve(l);
	for (int i = 0; i < l; i++)
	{
		Vec_ZZ vec = bitdecomp_1(C1[i]);
		C1_prim.push_back(vec);
	}

	ZZ z;
	for (int i = 0; i < l; i++)
	{
		ZZ elem(0);
		
		for (int j = 0; j < l; j++)
		{
			elem += C2[i][j] * C1[j][0];
		}

		Vec_ZZ linie;
		linie.push_back(elem);
		linie = bitdecomp(linie);
		C_mult.push_back(linie);
	}

	return (C_mult);
}