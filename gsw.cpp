#include "gsw.h"
#include <assert.h>
#include <NTL/ZZ_p.h>

GSWParams::GSWParams(int lambda, int L)
{
	n = lambda*L;

	// RandomBits(q, lambda*L);
	do
	{
		RandomBits(q, 4);
	} while (q == 0 );


	ZZ qp = q;

	while (qp != 0)
	{
		log_q++;
		qp /= 2;
	}

	m = n * log_q;

	// chi_Bound <= w(log n) *n^(1/2)
	int log_n = 0;
	int copy_n = n;
	while (copy_n != 0)
	{
		log_n++;
		copy_n /= 2;
	}

	// ?????????????????????????
	chi_Bound = ZZ ( log_n * (int)sqrt(n) ); 
	// ?????????????????????????

	setup_completed = true;
}

vector<ZZ> GSWParams::sampleFromChiDistribution()const
{
	vector<ZZ> error;

	ZZ_p::init(chi_Bound);
	ZZ e_i;

	for (int i = 0; i < m; i++)
	{
		conv(e_i, random_ZZ_p());
		error.push_back(e_i);
	}

	assert(error.size() == m);
	return error;
}

ZZ GSWParams::get_v_i(int &i)const
{
	ZZ v_i(0);
	/*ZZ q_4 = q / 4;
	ZZ q_2 = q / 2;

	for (int i = 0; i < v.size(); i++)
	{

	}*/

	int l = log_q + 1;
	v_i = v[l];

	assert(v[l] > q / 4);
	assert(v[l] <= q / 2);

	return v_i;
}

void GSWParams::set_v(vector<ZZ> vec)
{
	v = vec;
}

void SecretKeyGen(GSWParams params, vector<ZZ> &t, vector<ZZ> &sk, vector<ZZ> &v)
{
	assert(params.get_setup_state() != false);

	// esantioneaza t din Z^n_q
	ZZ t_i;
	int n = params.get_n();
	ZZ q = params.get_q();
	ZZ_p::init(q);

	sk.push_back(ZZ(1));
	
	for (int i = 0; i < n; i++)
	{
		conv(t_i, random_ZZ_p());
		t.push_back(t_i);
		sk.push_back( ZZ(-1) * t_i );
	}

	// se calculeaza v = powerOf2(s);
	vector<ZZ> powers_of_elem;
	int l = params.get_log_q() + 1;

	for (int j = 0; j < sk.size(); j++)
	{
		powers_of_elem = powers_of_2_from_ZZ(sk[j], l);
		for (int k = 0; k < l; k++)
		{
			v.push_back(powers_of_elem[k]);
		}
	}
}

void PublicKeyGen(GSWParams params, vector<ZZ> t, vector<vector<ZZ> > &A)
{
	int n = params.get_n();
	int m = params.get_m();
	ZZ q = params.get_q();
	vector<vector<ZZ> > B = GenerateMatrix(m, n, q);

	vector<ZZ> b;
	ZZ b_i;

	// B * t;
	for (int i = 0; i < m; i++)
	{
		b_i = 0;
		for (int j = 0; j < n; j++)
		{
			b_i += B[i][j] * t[j];
		}
		b.push_back(b_i);
	}

	vector<ZZ> error = params.sampleFromChiDistribution();

	// b = B * t + e
	for (int i = 0; i < m; i++)
	{
		b[i] = b[i] + error[i];
		b[i] = b[i] % q;
	}

	// set A = (b | B)
	// A[0] = prima coloana, adica b

	vector<ZZ> linie_A;

	for (int i = 0; i < m; i++)
	{
		linie_A.push_back(b[i]);
		for (int j = 0; j < n; j++)
		{
			linie_A.push_back(B[i][j]);
		}

		A.push_back(linie_A);

		linie_A.clear();
	}

}

vector<vector<ZZ> > Enc(GSWParams params, vector<vector<ZZ> > pk, int miu)
{
	int n = params.get_n();
	int m = params.get_m();
	ZZ q = params.get_q();

	int l = params.get_log_q() + 1;
	int N = (n + 1);

	vector<vector<ZZ> > R = GenerateMatrix(N, m, ZZ(2));

	vector<vector<ZZ> > C_prim = BitDecomp(matrixMult(R, pk, q), l);

	for (int i = 0; i < N; i++)
	{
		C_prim[i][i] = C_prim[i][i] + miu;
	}

	cout << "C_prim" << endl;
	for (int i = 0; i < C_prim.size(); i++)
	{
		for (int j = 0; j < C_prim[0].size(); j++)
		{
			cout << C_prim[i][j] << " ";
		}
		cout << endl;
	}

	vector<vector<ZZ> > C;
	C = Flatten(C_prim, l);

	return C;
}

int Dec(GSWParams params, vector<ZZ> sk, vector<vector<ZZ> > C)
{
	int i;
	ZZ v_i = params.get_v_i(i); // v_i = 2^i;

	ZZ x_i = dotProduct(C[i], params.get_v());

	int miu;

	conv(miu, x_i / v_i);

	return miu;
}

int MPDec(GSWParams params, vector<ZZ> sk, vector<vector<ZZ> > C)
{
	// neimplementata inca
	assert(0);
	return 0;
}

vector<ZZ> binary_representation(ZZ a, int l)
{
	vector<ZZ> bin_rep;
	ZZ rest;

	// cout << "a =" << a << endl;
	// cout << "l = " << l << endl;

	for (int i = 0; i < l; i++)
	{
		rest = a % 2;
		bin_rep.push_back(rest);
		a = a / 2;
	}

	if (a != 0 )
	{
		cout << "a =" << a << endl;
		cout << "l = " << l << endl;
	}

	assert(a == 0);		// daca a nu este egal cu 0 inseamna ca a 
						// nu poate fi reprezentat pe l biti

	return bin_rep;
}

vector<vector<ZZ> > BitDecomp(vector<vector<ZZ> > A, int l)
{
	vector<vector<ZZ> > bitdecomp_A;
	vector<ZZ> a_i;
	
	for (int i = 0; i < A.size(); i++)
	{
		vector<ZZ> a_i_l;
		bitdecomp_A.push_back(a_i_l);

		for (int j = 0; j < A[i].size(); j++)
		{
			a_i = binary_representation(A[i][j], l);
			assert(a_i.size() == l);

			/*for (int i = 0; i < l; i++)
			{
				cout << "a_i[" << i << "] = " << a_i[i] << endl;
			}*/

			
			for (int k = 0; k < l; k++)
			{
				bitdecomp_A[i].push_back(a_i[k]);
			}
		}
	}

	return bitdecomp_A;
}

ZZ bin_to_ZZ(vector<ZZ> vec, int l)
{
	ZZ a_i(1);
	ZZ doi(2);
	ZZ power_of_two(1);

	for (int i = 0; i < l; i++)
	{
		a_i = a_i + vec[i] * power_of_two;
		power_of_two *= doi;
	}

	return a_i;
}

vector<vector<ZZ> > BitDecomp_1(vector<vector<ZZ> > A, int l)
{
	vector<vector<ZZ> > inv_bitdec;
	vector<ZZ> a_i;

	for (int i = 0; i < A.size(); i++)
	{
		vector<ZZ> linie;
		inv_bitdec.push_back(linie);

		for (int j = 0; j < A[i].size(); j+=l)
		{
			assert((j + l) <= A[i].size());

			for (int k = 0; k < l; k++)
			{
				a_i.push_back(A[i][j]);
			}

			inv_bitdec[i].push_back(bin_to_ZZ(a_i, l));

			a_i.clear();
		}
	}

	return inv_bitdec;
}

vector<ZZ> powers_of_2_from_ZZ(ZZ elem, int l)
{
	vector<ZZ> powers_of_2;
	ZZ doi(2);
	ZZ power2(1);

	for (int i = 0; i < l; i++)
	{
		powers_of_2.push_back(power2*elem);
		power2 *= doi;
	}

	return powers_of_2;
}

vector<ZZ> powers_of_2_to_ZZ(vector<ZZ> powers, int l)
{
	vector<ZZ> vec;
	for (int i = 0; i < l; i++)
	{
		vec.push_back(powers[i*l]);
	}

	return vec;
}

vector<vector<ZZ> > PowersOf2(vector<vector<ZZ> > b, int l)
{
	vector<vector<ZZ> > powers_of_2;
	vector<ZZ> powers_elem;

	for (int i = 0; i < b.size(); i++)
	{
		for (int j = 0; j < b[i].size(); j++)
		{
			powers_elem = powers_of_2_from_ZZ(b[i][j], l);
			for (int k = 0; k < l; k++)
			{
				powers_of_2[i].push_back(powers_elem[k]);
			}
		}
	}

	return powers_of_2;
}

vector<vector<ZZ> > Flatten(vector<vector<ZZ> > C_prim, int l)
{
	return BitDecomp(BitDecomp_1(C_prim,l), l);
}

vector<vector<ZZ> > GenerateMatrix(int n, int m, ZZ modulus_q)
{
	vector<vector<ZZ> > R;

	ZZ_p::init(modulus_q);
	// cout << "q = " << modulus_q << endl;

	ZZ R_i_j;

	for (int i = 0; i < n; i++)
	{
		vector<ZZ> R_i;
		R.push_back(R_i);

		for (int j = 0; j < m; j++)
		{
			conv(R_i_j, random_ZZ_p());
			R[i].push_back(R_i_j);
		}
	}

	return R;
}

vector<vector<ZZ> > matrixMult(vector<vector<ZZ> > M1, vector<vector<ZZ> > M2, ZZ q)
{
	assert(M1[0].size() == M2.size());
	assert(M1.size() != 0);
	assert(M1[0].size() != 0);
	assert(M2.size() != 0);
	assert(M2[0].size() != 0);

	vector<vector<ZZ> > produs;
	int linii = M1.size();
	int coloane = M2[0].size();
	ZZ elem;

	for (int i = 0; i < linii; i++)
	{
		vector<ZZ> linie;
		produs.push_back(linie);
		for (int j = 0; j < linii; j++)
		{
			elem = 0;
			for (int k = 0; k < coloane; k++)
			{
				elem += M1[j][k] * M2[k][j];
			}

			elem = elem % q;
			produs[i].push_back(elem);	// produs[i][j] = elem
		}
	}

	/*for (int i = 0; i < M1.size(); i++)
	{
		for (int j = 0; j < M2[0].size(); j++)
		{
			cout << produs[i][j] << " ";
		}
		cout << endl;
	}*/

	return produs;
}

vector<vector<ZZ> > matrixAdd(vector<vector<ZZ> > M1, vector<vector<ZZ> > M2)
{
	assert(M1.size() != 0);
	assert(M2.size() != 0);
	assert(M1.size() != M2.size());

	vector<vector<ZZ> > sum;
	int coloane = M1[0].size();
	int linii = M1.size();

	for (int i = 0; i < linii; i++)
	{
		for (int j = 0; j < coloane; j++)
		{
			sum[i].push_back(M1[i][j] + M2[i][j]);
		}
	}

	return sum;
}

ZZ dotProduct(vector<ZZ> v1, vector<ZZ> v2)
{
	assert(v1.size() == v2.size());

	ZZ dot_product(0);
	int length = v1.size();
	for (int i = 0; i < length; i++)
	{
		dot_product += v1[i] * v2[i];
	}

	return dot_product;
}