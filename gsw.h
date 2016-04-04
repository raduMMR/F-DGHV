#pragma once
#include <vector>
#include <NTL/ZZ.h>
using namespace std;
using namespace NTL;

class GSWParams
{
	ZZ q;	// modulus q
	int log_q; // log_2 (q)
	int n;	// lattice dimension
	int m;	// m = O(n log q)
	bool setup_completed = false;

	ZZ chi_Bound;

	vector<ZZ> v;

public:

	GSWParams(int lambda, int L);

	ZZ get_q()const
	{
		return q;
	}

	int get_log_q()const
	{
		return log_q;
	}

	int get_n()const
	{
		return n;
	}

	int get_m()const
	{
		return m;
	}

	bool get_setup_state()const
	{
		return setup_completed;
	}

	vector<ZZ> sampleFromChiDistribution()const;

	vector<ZZ> get_v()const
	{
		return v;
	}

	ZZ get_v_i(int &i)const;

	void set_v(vector<ZZ> vec);
};


/*
@brief genereaza cheia secreta sub forma unui vector t de lungime n
		si un vector v = Powersof2(s), vectorul propriu
*/
void SecretKeyGen(GSWParams params, vector<ZZ> &t, vector<ZZ> &sk, vector<ZZ> &v);

/*
@brief genereaza cheia secreta sub forma matrcii A
*/
void PublicKeyGen(GSWParams params, vector<ZZ> t, vector<vector<ZZ> > &A);

/*
@brief cripteaza cu schema GSW un mesaj
*/
vector<vector<ZZ> > Enc(GSWParams params, vector<vector<ZZ> > pk, int miu);

/*
@brief decripteaza cu schema GSW un mesaj
*/
int Dec(GSWParams params, vector<ZZ> sk, vector<vector<ZZ> > C);

/*
@brief neimplementata - o alta metoda de decriptare 
*/
int MPDec(GSWParams params, vector<ZZ> sk, vector<vector<ZZ> > C);

/*
@brief metoda de BitDecomp aplicata fiecarei linii a matricii A
@param A matricea ale carei linii vor fi supuse la BitDecomp
@param l = [log q] + 1 
@return matricea cu liniile transformate potrivit lui BitDecomp
*/
vector<vector<ZZ> > BitDecomp(vector<vector<ZZ>> A, int l);


/*
@brief metoda BitDecomp_1 aplicata fiecarei linii a matricii A
@param A matricea de intrare
@param l = [log q]+1
@return matricea de iesire cu liniile calculate dupa BitDecomp_1
*/
vector<vector<ZZ>> BitDecomp_1(vector<vector<ZZ> > A, int l);

/*
@brief metoda Powersof2 aplicata vectorului b
@param b vectorul de intrare b
@param l = [log q] +1
@return vectorul rezultat in urma transformarii Powersof2
*/
vector<vector<ZZ> > PowersOf2(vector<ZZ> b, int l);

/*
@brief Flatten = BitDecomp( BitDecomp_1 (C,l), l)
*/
vector<vector<ZZ> > Flatten(vector<vector<ZZ> > C, int l);

// functii ajutatoare
/*
@brief genereaza o matrice n x m cu valori intregi in [0, q)
*/
vector<vector<ZZ> > GenerateMatrix(int n, int m, ZZ modulus_q);

/*
@brief inmultire a doua matrici
TODO : imbunatatirea inmultirii cu metoda Coppersmith
*/
vector<vector<ZZ> > matrixMult(vector<vector<ZZ> > M1, vector<vector<ZZ> > M2);

/*
@brief adunare de matrici
*/
vector<vector<ZZ> > matrixAdd(vector<vector<ZZ> > M1, vector<vector<ZZ> > M2);

/*
@brief produsul scalar intre doi vectori
*/
ZZ dotProduct(vector<ZZ> v1, vector<ZZ> v2);

/*
@brief descompunerea in reprezentarea binara pe l biti a numarului a
*/
vector<ZZ> binary_representation(ZZ a, int l);

/*
@brief compunerea unui numar din reprezentarea binara in cea zecimala
*/
ZZ bin_to_ZZ(vector<ZZ> vec, int l);

/*
@brief reconstructia elementelor unui vector dintr-un vector expandat cu powerof2
	din v = ( a_0, 2*a_0, ..., 2^(l-1)*a_0,..., a_(l-1), 2*a_(l-1), ..., 2^(l-1)*a_(l-1) )
	in v = (a_0, a_1, ..., a_(l-1))

*/
vector<ZZ> powers_of_2_to_ZZ(vector<ZZ> powers, int l);

/*
@brief construirea unui vector de lungime l de forma 
	v = ( elem, 2*elem, 2^2 * elem, ..., 2^(l-1)*elem)
*/
vector<ZZ> powers_of_2_from_ZZ(ZZ elem, int l);



