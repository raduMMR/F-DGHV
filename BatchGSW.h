#pragma once

#include <iostream>
#include <vector>
using namespace std;

class BatchGSW
{
	int *v;		// v = PowersOf2(1) cu coeficienti { 2^i : i = [1,l-1] }
	int l;		// l = [ log x_0 ] + 1

	long enc_0; 
	long p;
	int lambda;

public:
	BatchGSW();

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

};
