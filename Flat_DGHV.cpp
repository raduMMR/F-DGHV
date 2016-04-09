#include "Flat_DGHV.h"
#include "Params.h"
#include "utilities.h"
#include <assert.h>

Flat_DGHV::Flat_DGHV(int lambda)
{
	// this->lambda = lambda;

	compute_DGHV_settings(lambda);

	l = 0;					// l = log x_0 + 1
	ZZ x_0 = pk_DGHV[0];
	while (x_0 != 0)
	{
		l++;
		x_0 = x_0 / 2;
	}
	assert(l != 0);
	l += 1;

	v.SetLength(l);			// v = Powersof2(1);
	ZZ two(2);
	ZZ pow_of_two(1);
	for (int i = 0; i < l; i++)
	{
		v[i] = pow_of_two;
		pow_of_two *= 2;
	}

	C_prim.SetDims(l, 1);

	for (int i = 0; i < l; i++)
	{
		// o criptare noua pentru fiecare linie a matricii C_prim
		C_prim[i][0] = encrypt_DGHV(0);
	}
}

void Flat_DGHV::compute_DGHV_settings(int lambda)
{
	long ro = lambda;
	long ro_prim = 2 * lambda;
	long eta = lambda*lambda;
	long gamma = pow(lambda, 4);
	long tau = gamma + lambda;

	Params::set_params(gamma, eta, ro, tau, ro_prim);

	generate_keys(sk_DGHV, pk_DGHV);
}

ZZ	Flat_DGHV::encrypt_DGHV(int message)const
{
	return encrypt_integer(pk_DGHV, ZZ(message));
}

int	Flat_DGHV::decrypt_DGHV(ZZ &ctxt)const
{
	return ( ctxt % sk_DGHV % 2 );
}

void Flat_DGHV::bitdecomp(Mat<ZZ> &C, int index)const
{
	Vec<ZZ> C_decomp;
	long length = C.NumCols * l;
	C_decomp.SetLength(length);

	ZZ elem;
	for (int i = 0, j=-1; i < length; i++)
	{
		if (i % l == 0)
		{
			j++;
			elem = C[index][j];
		}

		C_decomp[i] = elem % 2;
		elem = elem / 2;
	}

	C[index] = C_decomp;

}

void Flat_DGHV::bitdecomp_1(Mat<ZZ> &C, int index)const
{
	Vec<ZZ> C_decomp_1;
	long length = C.NumCols / l;
	C_decomp_1.SetLength(length);

	ZZ pow_of_two(1);
	ZZ two(2);
	for (int i = 0, j = -1; i < C.NumCols; i++)
	{
		if (i % l == 0)
		{
			pow_of_two = 1;
			j++;
			C_decomp_1[j] = 0;
		}

		C_decomp_1[j] +=  C[index][i] * pow_of_two;
		pow_of_two *= two;
	}

	C[index] = C_decomp_1;
}

void Flat_DGHV::flatten(Mat<ZZ> &C)const
{
	for (int i = 0; i < C.NumRows; i++)
	{
		bitdecomp_1(C, i);
		C[i][0] = C[i][0] % pk_DGHV[0];
		bitdecomp(C, i);
	}
}

void Flat_DGHV::encrypt(int message, Mat<ZZ> &C)const
{
	C = C_prim;
	for (int i = 0; i < l; i++)
	{
		bitdecomp(C, i);
		C[i][i] += message;
	}
	flatten(C);
}

int Flat_DGHV::decrypt(Mat<ZZ> &C)const
{
	ZZ message(0);
	for (int i = 0; i < l; i++)
	{
		message += C[0][i] * v[i];
	}
	return decrypt_DGHV(message);
}

void Flat_DGHV::hom_add(Mat<ZZ> &C1, Mat<ZZ> &C2, Mat<ZZ> &C_add)const
{
	if (C_add.NumRows != l || C_add.NumCols != l)
	{
		C_add.SetDims(l, l);
	}

	for (int i = 0; i < l; i++)
	{
		for (int j = 0; j < l; j++)
		{
			C_add[i][j] = C1[i][j] + C2[i][j];
		}
	}

	flatten(C_add);
}

void Flat_DGHV::hom_mult(Mat<ZZ> &C1, Mat<ZZ> &C2, Mat<ZZ> &C_mult)const
{
	if (C_mult.NumCols != l || C_mult.NumRows != l)
	{
		C_mult.SetDims(l, l);
	}

	ZZ z;
	for (int i = 0; i < l; i++)
	{
		for (int j = 0; j < l; j++)
		{
			z = 0;
			for (int k = 0; k < l; k++)
			{
				z += C1[i][k] * C2[k][j];
			}
			C_mult[i][j] = z;
		}
	}

	flatten(C_mult);
}

