#include "BatchGSW.h"
#include <assert.h>
#include <time.h>

template<T>
T *aloca_memorie(int dim)
{
	T* vector;
	try
	{
		vector = new T[dim];
	}
	catch (bad_alloc& ba)
	{
		cerr << "bad alloc caught: " << ba.what() << endl;
	}

	return vector;
}

BatchGSW::BatchGSW()
{
	l = 0;
	v = NULL;
	int unu[] = { 1 };
	v = PowersOf2(unu, 1);

	// lambda - paramentrul reprezentand securitatea
	lambda = 10;

	// parametrii schemei de criptare simetrica DGHV
	int gamma = pow(lambda, 5);	
	int eta = pow(lambda, 2);	
	int ro_prim = 2 * lambda;

	long q;
	long r;
	long pow_of_2 = (long)pow((double)2, eta);

	srand(time(NULL));
	// genereaza cheia secreta
	do
	{
		p = rand() % (long)pow((double)2, eta - 1);
		p = p + pow_of_2; // sk apartine [ 2^(eta-1), 2^eta )

	} while (p % 2 != 1);

	// genereaza q
	q = rand() % (long)pow((double)2, gamma / p);

	// genereaza zgomot pentru criptare
	pow_of_2 = (long)pow((double)2, ro_prim+1);
	r = rand() % pow_of_2;
	pow_of_2 = (long)pow((double)2, ro_prim);
	r = r - pow_of_2;

	// cripteaza pe zero
	enc_0 = p*q + 2 * r + 0;

	// calculeaza l numarul de biti necesari reprezentarii criptarii lui l
	long copy_enc_0 = enc_0;
	do
	{
		l++;
		copy_enc_0 /= 2;
	} while (copy_enc_0 != 0);

	l += 1;
}

BatchGSW::~BatchGSW()
{
	if (v != NULL)
	{
		delete[] v;
	}
}

int* BatchGSW::BitDecomp(int *a, int n)
{
	int *bitdecomp = new int[n*l];
	int bit = 0;

	for (int i = 0; i < n; i++)
	{
		bit = a[i];
		for (int j = 0; j < l; j++)
		{
			bitdecomp[i*l + j] = bit % 2;
			bit = bit / 2;
		}

		assert(bit == 0);
	}

	return bitdecomp;
}

int** BatchGSW::matrix_BitDecomp(int **A, int m, int n)
{
	int **C = new int*[l];
	for (int i = 0; i < l; i++)
	{
		C[i] = new int[l];
	}

	for (int i = 0; i < n; i++)
	{
		C[i] = BitDecomp(A[i], n);
	}

	return C;
}

int* BatchGSW::BitDecomp_1(int *a, int n)
{
	int *vec = new int[n];
	int two_pow = 1;
	for (int i = 0; i < n; i++)
	{
		vec[i] = 0;
		two_pow = 1;
		for (int j = 0; j < l; j++)
		{
			vec[i] += two_pow * a[i*l + j];
			two_pow *= 2;
		}
	}

	return vec;
}

int** BatchGSW::matrix_BitDecomp_1(int **A, int m, int n)
{
	int **C = new int*[m];

	for (int i = 0; i < m; i++)
	{
		C[i] = BitDecomp_1(A[i], n);
	}

	return C;
}

int* BatchGSW::PowersOf2(int *a, int n)
{
	int* vec_pow2 = new int[n*l];
	int two_pow = 1;

	for (int i = 0; i < n; i++)
	{
		two_pow = 1;
		for (int j = 0; j < l; j++)
		{
			vec_pow2[i*l + j] = a[i] * two_pow;
			two_pow *= 2;
		}
	}

	return vec_pow2;
}

int** BatchGSW::matrix_PowersOf2(int **A, int m, int n)
{
	int **C = new int*[m];

	for (int i = 0; i < m; i++)
	{
		C[i] = PowersOf2(A[i], n);
	}

	return C;
}

int** BatchGSW::Flatten(int **A, int N)
{
	int **C = new int*[N];

	for (int i = 0; i < N; i++)
	{
		C[i] = BitDecomp(BitDecomp_1(A[i], N), N);
	}

	return C;
}

int** BatchGSW::GSW_Encrypt(int message)
{
	int **C = NULL;

	try
	{
		C = new int*[l];
	}
	catch (bad_alloc& ba)
	{
		cerr << "bad alloc caught: " << ba.what() << endl;
	}

	for (int i = 0; i < l; i++)
	{
		C[i] = NULL;
		try
		{
			C[i] = new int[1];
			C[i][0] = enc_0;
		}
		catch (bad_alloc& ba)
		{
			cerr << "bad alloc caught: " << ba.what() << endl;
		}
	}

	for (int i = 0; i < l; i++)
	{
		C[i][i] += message;
	}

	C = Flatten(C, l);

	return C;
}

int BatchGSW::GSW_Decrypt(int **C)
{
	int enc_miu = 0;

	for (int i = 0; i < l; i++)
	{
		enc_miu += C[0][i] * v[i];
	}

	return enc_miu;
}