#pragma once
#include <iostream>
#include <NTL\ZZ.h>
#include <NTL\matrix.h>
#include <vector>
using namespace std;
using namespace NTL;

typedef vector<vector<ZZ> > Mat_ZZ;
typedef vector<ZZ> Vec_ZZ;

/*
@brief clasa care implementeaza FHE peste intregi
	folosind tehnicile de Flattening descrise pentru schema GSW
*/
class Flat_DGHV
{
	/*
	@field vectorul cheie secreta v = Powersof2(1)
	*/
	Vec_ZZ v;

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
	Mat_ZZ C_prim;

	/*
	metodele private care vor fi folosite pentru tehnicile implementate de schema
	*/

	/*
	@brief metoda in care se calculeaza parametrii apartinand 
		schemei DGHV : x_0, sk_DGHV, l - dimensiunea unei matrici ciphertext
		aceste valori depind se parametrul de securitate lambda
	*/
	void	compute_DGHV_settings(char *filename, int lambda);

	void	compute_DGHV_settings(int lambda);

	void	compute_FDGHV_settings();

	ZZ		encrypt_DGHV(int message)const;

	int		decrypt_DGHV(ZZ &ctxt)const;

	Vec_ZZ	bitdecomp(Vec_ZZ &C_i)const;		// BitDecomp(a) = {a_0, a_1, ..., a_n} , a = a_0 + 2*a_1+... +2^(n)*n

	Vec_ZZ	bitdecomp_1(Vec_ZZ &C_i)const;		// BitDecomp(a_0, a_1, ..., a_n) = a , cu a = a_0 + 2*a_1+... +2^(n)*n

	Mat_ZZ	flatten(Mat_ZZ &C)const;			// Flatten(C)=BitDecomp( BitDecomp_1(C) % x_0 )

public:
	/*
	@brief constructorul clasei Flat_DGHV
	@param lambda - numarul reprezentand parametrul de securitate
			ex. 42 - toy security
			    52 - small
				62 - medium
				72 - good
	*/
	Flat_DGHV(char *filename, int lambda);

	/*
	@brief constructor in care sunt incarcate dintr-un fisier text 
		setarile generate la o rulare anterioara
	*/
	Flat_DGHV::Flat_DGHV(char *filename);

	Flat_DGHV::Flat_DGHV(int lambda);

	/*
	@brief criptare a unui mesaj intreg cu schema Flat_DGHV
	@param message - mesajul de criptat
	@return matricea C - ciphertext-ul rezultat in urma criptarii
	*/
	Mat_ZZ	encrypt(int message)const;

	/*
	@brief decriptare cu schema Flat_DGHV
	@param ref in C - ciphertext-ul care va fi decriptat
	@return valoarea intreaga obtinuta in urma decriptarii
	*/
	int		decrypt(Mat_ZZ &C)const;

	/*
	@brief adunare homomorfica a doua ciphertext-uri
		C_add = Flatten(C1+C2)
	@param in C1, C2 - matricile de intrare
	@return C_add - rezultatul adunarii ciphertext-urilor
	*/
	Mat_ZZ	hom_add(Mat_ZZ &C1, Mat_ZZ &C2)const;

	/*
	@brief inmultire homomorfica a doua ciphertext-uri
	C_add = Flatten(C1 * C2)
	@param in C1, C2 - matricile de intrare
	@return C_mult - rezultatul inmultirii ciphertext-urilor
	*/
	Mat_ZZ	hom_mult(Mat_ZZ &C1, Mat_ZZ &C2)const;

	/*
	@brief intoarce dimensiunea unei matrici ciphertext l x l
	*/
	long get_l()const { return l; }

	// TODO:
	// Mat_ZZ	add_constant(Mat_ZZ &C, int ct);
	// Mat_ZZ	mult_constant(Mat_ZZ &C, int ct);
	// Mat_ZZ	hom_NAND(Mat_ZZ &C1, Mat_Z   Z &C2);
	// Mat_ZZ	boostrapp(Mat_ZZ &C_noisy);
	// void		refresh_scheme_settings(int new_lambda);

	~Flat_DGHV() {}


	/*
	@brief multiplicare a matricilor optimizata
		BitDecomp_1( BitDecomp(C1) * BitDecomp(C2) ) = BitDecomp(C1) * C2
	*/
	Mat_ZZ	hom_mult_opt(Mat_ZZ &C1, Mat_ZZ &C2)const;


};

