#pragma once

#include <iostream>
#include <vector>
using namespace std;

// #define _DEBUG
// #define _PRINT

class BatchGSW
{
	int *v;		// v = PowersOf2(1) cu coeficienti { 2^i : i = [1,l-1] }
	int l;		// l = [ log x_0 ] + 1

	long enc_0; 
	long x_0;

public:
	BatchGSW(long x_0, long enc_0);

	~BatchGSW();

	int* BitDecomp(int *a, int n);

	int** matrix_BitDecomp(int **A, int m, int n);

	int* BitDecomp_1(int *a, int n);

	int** matrix_BitDecomp_1(int **A, int m, int n);

	int* PowersOf2(int *a, int n);

	int** matrix_PowersOf2(int **A, int m, int n);

	int** Flatten(int **A, int N);

	int** GSW_Encrypt(int message);

	int GSW_Decrypt(int **C);

	int get_l()const
	{
		return l;
	}

};




// functi ajutatoare

int** matrix_mult(int **A, int **B, int l);

int **matrix_add(int **A, int **B, int l);

/*template<T>T *aloca_memorie(int dim)
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
}*/
