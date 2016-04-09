#include "BatchGSW.h"
#include <assert.h>
#include <time.h>

BatchGSW::BatchGSW(long x_0, long enc_0)
{
	assert(x_0 != 0);

	l = 0;
	v = NULL;

	this->x_0 = x_0;
	this->enc_0 = enc_0;

	while (x_0 != 0)
	{
		l++;
		x_0 = x_0 / 2;
	}

	// l += 2;
	l = l*l;

	int unu[] = { 1 };
	v = PowersOf2(unu, 1);

#ifdef _TEST
	cout << "log_x_0 + 1 = l = " << l << endl;
	/*cout << "V = " << endl;
	for (int i = 0; i < l; i++)
	{
		cout << "v[" << i << "] = " << v[i] << endl;
	}*/

#endif

	// batching secret keys
	try
	{
		batch_v = new int*[l];
	}
	catch (bad_alloc& ba)
	{
		cerr << "bad alloc caught: " << ba.what() << endl;
	}

	for (int i = 0; i < l; i++)
	{
		batch_v[i] = batch_PowersOf2(unu, 1, i);

#ifdef _PRINT
		cout << "v[" << i << "]={";
		for (int j = 0; j < l; j++)
		{
			cout << batch_v[i][j] << " ,";
		}
		cout << "}\n";
#endif
	}

}

BatchGSW::~BatchGSW()
{
	if (v != NULL)
	{
		delete[] v;
	}

	if (batch_v != NULL)
	{
		for (int i = 0; i < l; i++)
			delete[] batch_v[i];
		delete[] batch_v;
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

		// assert(bit == 0);
	}

#ifdef _TEST

	cout << "\nBitDecomp\n";
	for (int i = 0; i < n*l; i++)
	{
		cout << bitdecomp[i];
		if ((i-5) % l == 0 )
		{
			cout << endl;
		}	
		else
		{
			cout << ", ";
		}

	}
	cout << endl << endl;

#endif // _DEBUG


	return bitdecomp;
}

int** BatchGSW::matrix_BitDecomp(int **A, int m, int n)
{
	assert(m == l);

	int **C = new int*[l];

	for (int i = 0; i < l; i++)
	{
		C[i] = BitDecomp(A[i], 1);
	}

	return C;
}

int* BatchGSW::BitDecomp_1(int *a, int n)
{
	assert(n != 0);
	assert(n % l == 0);

	int dim = n / l;

	int *vec = new int[dim];
	int two_pow = 1;
	for (int i = 0; i < dim; i++)
	{
		vec[i] = 0;
		two_pow = 1;
		for (int j = 0; j < l; j++)
		{
			vec[i] += two_pow * a[i*l + j];
			two_pow *= 2;
		}
	}

#ifdef _TEST

	cout << "BitDecomp_1\n";
	for (int i = 0; i < dim; i++)
	{
		cout << vec[i] << ", ";
	}

#endif // _DEBUG

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

#ifdef _TEST

	cout << "\n\nPowersOf2 DEBUG\n";

	for (int i = 0; i < n*l; i++)
	{
		cout << vec_pow2[i] << ", ";
	}
	cout << endl;

#endif

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
	assert(A != NULL);
	assert(N != 0);
	assert(N % l == 0);

	int **C = new int*[N];

	for (int i = 0; i < N; i++)
	{
		C[i] = BitDecomp(BitDecomp_1(A[i], N), N/l);
	}

	return C;
}

int** BatchGSW::Flatten_mod_x_0(int **A, int N)
{
	assert(A != NULL);
	assert(N != 0);
	assert(N % l == 0);

	int **C = new int*[N];
	int *C_intermediar = NULL;

	for (int i = 0; i < N; i++)
	{
		C_intermediar = BitDecomp_1(A[i], N);

		for (int j = 0; j < N / l; j++)
		{
			C_intermediar[j] = C_intermediar[j] % x_0;
		}

		C[i] = BitDecomp(C_intermediar, N / l);
	}

	return C;
}

int** BatchGSW::GSW_Encrypt(int message)
{
	int **C = NULL;
	int **C_prim = NULL;

	try
	{
		C_prim = new int*[l];
	}
	catch (bad_alloc& ba)
	{
		cerr << "bad alloc caught: " << ba.what() << endl;
	}

	for (int i = 0; i < l; i++)
	{
		C_prim[i] = NULL;
		try
		{
			C_prim[i] = new int[1];
			C_prim[i][0] = enc_0;
#ifdef _PRINT
			cout << C_prim[i][0] << endl;
#endif
		}
		catch (bad_alloc& ba)
		{
			cerr << "bad alloc caught: " << ba.what() << endl;
		}
	}

	C = matrix_BitDecomp(C_prim, l, 1);

#ifdef _PRINT
	cout << "\nBitDecomp( C_prim )\n\n";
#endif

	for (int i = 0; i < l; i++)
	{
#ifdef _PRINT
		for (int j = 0; j < l; j++)
		{
			cout << C[i][j] << " ";
		}
		cout << endl;
#endif
		C[i][i] += message;
	}

#ifdef _PRINT
	cout << endl << endl;
#endif

	C = Flatten(C, l);

#ifdef _PRINT
	cout << "\nCiphertext\n\n";
	for (int i = 0; i < l; i++)
	{
		for (int j = 0; j < l; j++)
		{
			cout << C[i][j] << " ";
		}
		cout << endl;
	}
	cout << endl;
#endif

	// cleanup memory
	for (int i = 0; i < l; i++)
	{
		delete[] C_prim[i];
	}
	delete[] C_prim;

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

int** BatchGSW::matrix_mult(int **A, int **B, int l)
{
	int **M = new int*[l];
	for (int i = 0; i < l; i++)
	{
		M[i] = new int[l];
		for (int j = 0; j < l; j++)
		{
			M[i][j] = 0;
			for (int k = 0; k < l; k++)
			{
				// M[i][j] += A[i][k] * B[k][j] % 2;
				M[i][j] += A[i][k] * B[k][j];
			}
		}
	}

	return M;
}

int** BatchGSW::matrix_add(int **A, int **B, int l)
{
	int **M = new int*[l];

	for (int i = 0; i < l; i++)
	{
		M[i] = new int[l];
		for (int j = 0; j < l; j++)
		{
			// M[i][j] = A[i][j] + B[i][j] % 2;
			M[i][j] = A[i][j] + B[i][j];
		}
	}

	return M;
}


/***************			BATCHING GSW				*******/

int** BatchGSW::batch_GSW_Enc(int *message)
{
	int **C = new int*[l];
	int **C_prim = new int*[l];

	for (int i = 0; i < l; i++)
	{
		C_prim[i] = new int[1];
		C_prim[i][0] = enc_0;
	}

	C = batch_matrix_BitDecomp(C_prim, l, 1);

	for (int i = 0; i < l; i++)
	{
		C[i][i] += message[i];
	}

	C = batch_Flatten_mod_x_0(C, l);

	// cleanup
	for (int i = 0; i < l; i++)
	{
		delete[] C_prim[i];
	}
	delete[] C_prim;

	return C;
}

int* BatchGSW::batch_GSW_Dec(int **C)
{
	int *m = new int[l];

	int enc_miu = 0;

	for (int i = 0; i < l; i++)
	{
		m[i] = 0;
		for (int j = 0; j < l; j++)
		{
			m[i] += C[i][j] * batch_v[i][j];
		}
	}
	
	return m;
}

int* BatchGSW::batch_BitDecomp(int *a, int n, int shift)
{
	int *bitdecomp = new int[n*l];
	int bit = 0;

	for (int i = 0; i < n; i++ )
	{
		bit = a[i];
		for (int j = 0, k = shift; j < l; j++, k = (k + 1) % l)
		{
			bitdecomp[i*l + k] = bit % 2;
			bit = bit / 2;
		}
	}

	return bitdecomp;
}

int* BatchGSW::batch_BitDecomp_1(int *a, int n, int shift)
{
	assert(n != 0);
	assert(n % l == 0);
	int dim = n / l;

	int *vec = new int[dim];
	int two_pow = 1;
	for (int i = 0; i < dim; i++)
	{
		vec[i] = 0;
		two_pow = 1;
		for (int j = 0, k = shift; j < l; j++, k = (k + 1) % l)
		{
			vec[i] += two_pow * a[i*l + k];
			two_pow *= 2;
		}
	}
	return vec;
}

int* BatchGSW::batch_PowersOf2(int *a, int n, int shift)
{
	int* vec_pow2 = NULL;

	try
	{
		vec_pow2 = new int[n*l]; 
	}
	catch (bad_alloc& ba)
	{
		cerr << "bad alloc caught: " << ba.what() << endl;
	}
	
	int two_pow = 1;

	for (int i = 0; i < n; i++)
	{
		two_pow = 1;
		for (int j = 0, k = shift; j < l; j++, k = (k + 1) % l)
		{
			vec_pow2[i*l + k] = a[i] * two_pow;
			two_pow *= 2;
		}
	}

	return vec_pow2;
}

int** BatchGSW::batch_matrix_BitDecomp(int **A, int m, int n)
{
	// pentru F-DGHV
	assert(m == l);
	assert(n == 1);

	int **C = new int*[l];

	// cout << "\n\t batch matrix BitDecomp \n\n";
	for (int i = 0; i < l; i++)
	{
		C[i] = batch_BitDecomp(A[i], n, i);
		/*for (int j = 0; j < l; j++)
		{
			cout << C[i][j] << " ";
		}
		cout << endl;*/
	}

	return C;
}

int** BatchGSW::batch_matrix_BitDecomp_1(int **A, int m, int n)
{
	// pentru F-DGHV
	assert(m == l);
	assert(n == l);

	int **C = new int*[m];

	// cout << "\n\t batch matrix BitDecomp_1 \n\n";
	for (int i = 0; i < m; i++)
	{
		C[i] = batch_BitDecomp_1(A[i], n, i);
		C[i][0] = C[i][0] % x_0;
		// cout << C[i][0] << endl;
	}

	return C;
}

int** BatchGSW::batch_matrix_PowersOf2(int **A, int m, int n)
{
	int **C = new int*[m];

	for (int i = 0; i < m; i++)
	{
		C[i] = batch_PowersOf2(A[i], n, i);
	}

	return C;
}

int** BatchGSW::batch_Flatten_mod_x_0(int **A, int N)
{
	assert(A != NULL);
	assert(N != 0);
	assert(N % l == 0);

	int **C = new int*[N];
	int *C_intermediar = NULL;

	int **C_prim = NULL;

	C_prim = batch_matrix_BitDecomp_1(A, l, l);

	// reducerea modulo x_0
	for (int i = 0; i < l; i++)
	{
		C_prim[i][0] = C_prim[i][0] % x_0;
	}

	C = batch_matrix_BitDecomp(C_prim, l, 1);

	// cleanup 
	for (int i = 0; i < l; i++)
	{
		delete[] C_prim[i];
	}
	delete[] C_prim;

	return C;
}