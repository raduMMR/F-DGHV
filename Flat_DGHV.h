#pragma once
#include <iostream>
#include <NTL\ZZ.h>
#include <NTL\vector.h>
#include <NTL\matrix.h>
#include <vector>
using namespace std;
using namespace NTL;

/*
@brief clasa care implementeaza FHE peste intregi
	folosind tehnicile de Flattening descrise pentru schema GSW
*/
class Flat_DGHV
{
	/*
	@field vectorul cheie secreta v = Powersof2(1)
	*/
	Vec<ZZ> v;

	/*
	@field l = log x_0 + 1, numarul de biti necesari reprezentarii
		unui ciphertext al schemei DGHV
		dimensiunea unui ciphertext
	*/
	long l;

	/*
	campul care stabileste nivelul de securitate pentru schema DGHV
	in functie de el fiind derivati toti ceilalti parametri
	*/
	// int lambda;

	/*
	cheia secreta pentru schema DGHV, care va fi folosita si la decriptarea
	schemei Flat_DGHV
	*/
	ZZ sk_DGHV;

	/*
	vectorul cheie publica pentru schema DGHV, pk[0] = x_0
	toate valorile dupa bitdecomp_1 se reduc modulo x_0
	*/
	vector<ZZ> pk_DGHV;

	/*
	matrice de dimensiune l x 1 care va fi completa la criptarea
	unui mesaj nou pe fiecare linie cu
	o criptare noua a lui 0, adica C_prim = (Enc(0)[0], 
										Enc(0)[1], 
										Enc(0)[2], 
										..., 
										Enc(0)[l-1] )
	*/
	Mat<ZZ> C_prim;

	/*
	metodele private care vor fi folosite pentru tehnicile implementate de schema
	*/

	/*
	@brief metoda in care se calculeaza parametrii apartinand 
		schemei DGHV : x_0, sk_DGHV, l - dimensiunea unei matrici ciphertext
		aceste valori depind se parametrul de securitate lambda
	*/
	void	compute_DGHV_settings(int lambda);

	void	compute_FDGHV_settings();

	ZZ		encrypt_DGHV(int message)const;

	int		decrypt_DGHV(ZZ &ctxt)const;

	void	bitdecomp(Mat<ZZ> &C, int index)const;		// BitDecomp(a) = {a_0, a_1, ..., a_n} , a = a_0 + 2*a_1+... +2^(n)*n

	void	bitdecomp_1(Mat<ZZ> &C, int index)const;		// BitDecomp(a_0, a_1, ..., a_n) = a , cu a = a_0 + 2*a_1+... +2^(n)*n

	void	flatten(Mat<ZZ> &C)const;	// Flatten(C)=BitDecomp( BitDecomp_1(C) % x_0 )

public:
	/*
	@brief constructorul clasei Flat_DGHV
	@param lambda - numarul reprezentand parametrul de securitate
			ex. 42 - toy security
			    52 - small
				62 - medium
				72 - good
	*/
	Flat_DGHV(int lambda);

	/*
	@brief constructor in care sunt incarcate dintr-un fisier text 
		setarile generate la o rulare anterioara
	*/
	Flat_DGHV::Flat_DGHV();

	/*
	@brief criptare a unui mesaj intreg cu schema Flat_DGHV
	@param message - mesajul de criptat
	@param ref out C - ciphertext-ul rezultat in urma criptarii
	*/
	void encrypt(int message, Mat<ZZ> &C)const;

	/*
	@brief decriptare cu schema Flat_DGHV
	@param ref in C - ciphertext-ul care va fi decriptat
	@return valoarea intreaga obtinuta in urma decriptarii
	*/
	int decrypt(Mat<ZZ> &C)const;

	/*
	@brief adunare homomorfica a doua ciphertext-uri
		C_add = Flatten(C1+C2)
	@param in C1, C2 - matricile de intrare
	@param out C_add - rezultatul adunarii ciphertext-urilor
	*/
	void hom_add(Mat<ZZ> &C1, Mat<ZZ> &C2, Mat<ZZ> &C_add)const;

	/*
	@brief inmultire homomorfica a doua ciphertext-uri
	C_add = Flatten(C1 * C2)
	@param in C1, C2 - matricile de intrare
	@param out C_mult - rezultatul inmultirii ciphertext-urilor
	*/
	void hom_mult(Mat<ZZ> &C1, Mat<ZZ> &C2, Mat<ZZ> &C_mult)const;

	/*
	@brief intoarce dimensiunea unei matrici ciphertext l x l
	*/
	long get_l()const { return l; }

	// TODO:
	// void add_constant(Mat<ZZ> &C, int ct, Mat<ZZ> &C_add);
	// void mult_constant(Mat<ZZ> &C, int ct, Mat<ZZ> &C_mult);
	// void hom_NAND(Mat<ZZ> &C1, Mat<ZZ> &C2, Mat<ZZ> &C_nand);
	// void boostrapp(Mat<ZZ> &C_noisy, Mat<ZZ> &C_bootstrapped);
	// void refresh_scheme_settings(int new_lambda);

	~Flat_DGHV() {}
};

