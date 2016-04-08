#pragma once

#include <iostream>
#include <vector>
using namespace std;

// #define _DEBUG
// #define _PRINT

/*
@brief clasa pentru F-DGHV
	implementarea tehnicilor de Flattenig pentru schema de 
	criptare homomorfica peste intregi

	TODO : de adaugat operatii : MultConst, NAND, bootstrapping
*/
class BatchGSW
{
	int *v;		// v = PowersOf2(1) cu coeficienti { 2^i : i = [1,l-1] }
	int l;		// l = [ log x_0 ] + 1

	long enc_0; 
	long x_0;

	int **batch_v;

public:
	/*
	@brief constructor clasa BatchGSW, initializeaza cheia secreta v
				seteaza dimensiune l = log x_0 + 1
	@param x_0 cel mai mare intreg din cheia publica corespunzatoare schemei DGHV
	@param enc_0 criptare a lui zero cu schema DGHV 
	*/
	BatchGSW(long x_0, long enc_0);

	~BatchGSW();

	/*
	@brief BitDecomp( a[0], a[1],..., a[n-1]) = ( a[0][0],..., a[0][l-1],..., a[n-1][0],..., a[n-1][l-1]).
		a[i] = Suma dupa i din 2^j * a[i][j], j=1,..., l-1
		descompunerea in l biti a lui a[i] = (a[i][0], ..., a[i][l-1])
	
	@param a vectorul de descompus

	@param n dimensiunea vectorului a

	@return vectorul a descompus de dimensiune n x l
	*/
	int* BitDecomp(int *a, int n);

	/*
	@brief descompunerea dupa linii a unei matrici 
	@param A matricea de intrare
	@param m nr de linii
	@param n nr de coloane
	@return matricea A descompusa dupa linii
	*/
	int** matrix_BitDecomp(int **A, int m, int n);

	/*
	@brief inversa operatiei bitdecomp
	@param a vectorul de intrare cu k elemente descompuse fiecare pe l biti
	@param n dimensiune lui a, n = k x l
	@return vectorul reconstruit din biti de dimensiune k
	*/
	int* BitDecomp_1(int *a, int n);

	/*
	@brief bitdecomp_! aplicat fiecarei linii a matricii de intrare A
	@param A matricea de intrare
	@param m nr de linii
	@param n nr de coloane
	@return matricea rezultata in urma operatiilor
	*/
	int** matrix_BitDecomp_1(int **A, int m, int n);

	/*
	@brief inmulteste pe rand cu puterile lui 2 de la 0 la l-1, 
		elementele vectorului a
	@param a vectorul de intrare
	@param n dimensiunea vectorului de intrare
	@return vectorul cu l x n elemente
	*/
	int* PowersOf2(int *a, int n);

	/*
	@brief aplica powersof2 fiecarei linii a matricii de intrare
	@param A matricea de intrare
	@param m nr de linii ale matricii de intrare
	@param n nr de coloane ale matricii de intrare
	@return matricea transformata
	*/
	int** matrix_PowersOf2(int **A, int m, int n);

	/*
	@brief Flatten(C) = BitDecomp( BitDecomp_1(C) )
	@param C matricea de intrare
	@param N dimensiunile matricii C de intrare
	@return matricea rezultata dupa Flatten
	*/
	int** Flatten(int **C, int N);

	/*
	@brief metoda aplicata ctxt-urilor rezultate in urma 
		operatiilor homomorfice, reducere modulo x_0
	*/
	int** Flatten_mod_x_0(int **C, int N);

	/*
	@brief criptare cu schema F-DGHV
	@param message mesajul de criptat
	@return matrice ciphertext l x l 
	*/
	int** GSW_Encrypt(int message);

	/*
	@brief decriptare F-DGHV
	@param C - matricea ciphertext de intrare
	@return - mesajul decriptat
	*/
	int GSW_Decrypt(int **C);

	/*
	@get returneaza dimensiunea matricii ciphertext l x l 
	*/
	int get_l()const
	{
		return l;
	}


	// functii ajutatoare
	// TODO : de optimizat functiile, inmultirea matricilor cu Coppersmith

	/*
	@brief inmulteste doua matrici, inmultire neoptimizata "naiva"
	@param A, B matricile care se vor inmulti
	@param l dimensiunea matricilor l x l
	@return produsul inmultirii matricilor
	*/
	int** matrix_mult(int **A, int **B, int l);

	/*
	@brief adunare a doua matrici de dimensiune l x l
	@param A, B matricile de adunat
	@return rezultatul inmultirii
	*/
	int **matrix_add(int **A, int **B, int l);

	/*
	@brief criptare GSW cu batching
	@param m vectorul de mesaje binare ce vor fi criptate
		de dimensiune n = l
	@return matricea ciphertext GSW
	*/
	int**	batch_GSW_Enc(int *m);

	/*
	@brief decriptare GSW cu batching
	@param C matricea GSW ciphertext
	@return vectorul de mesaje decriptate de dimensiune l
	*/
	int*	batch_GSW_Dec(int **C);

	int*	batch_BitDecomp(int *a, int n, int shift);
	int*	batch_BitDecomp_1(int *a, int n, int shift);
	int*	batch_PowersOf2(int *a, int n, int shift);

	int**	batch_matrix_BitDecomp(int **A, int m, int n);
	int**	batch_matrix_BitDecomp_1(int **A, int m, int n);
	int**	batch_matrix_PowersOf2(int **A, int m, int n);
	int**	batch_Flatten_mod_x_0(int **C, int N);
};




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
