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

*/
vector<vector<ZZ>> BitDecomp_1(vector<vector<ZZ> > A, int l);

vector<vector<ZZ> > PowersOf2(vector<ZZ> b, int l);

vector<vector<ZZ> > Flatten(vector<vector<ZZ> > C, int l);

// functii ajutatoare
vector<vector<ZZ> > GenerateMatrix(int n, int m, ZZ modulus_q);
vector<vector<ZZ> > matrixMult(vector<vector<ZZ> > M1, vector<vector<ZZ> > M2);
vector<vector<ZZ> > matrixAdd(vector<vector<ZZ> > M1, vector<vector<ZZ> > M2);
ZZ dotProduct(vector<ZZ> v1, vector<ZZ> v2);
vector<ZZ> binary_representation(ZZ a, int l);
ZZ bin_to_ZZ(vector<ZZ> vec, int l);
vector<ZZ> powers_of_2_to_ZZ(vector<ZZ> powers, int l);
vector<ZZ> powers_of_2_from_ZZ(ZZ elem, int l);



