#include "utilities.h"
#include "gsw.h"
#include "BatchGSW.h"
#include <time.h>

void test_DGHV_scheme()
{
	// lambda - paramentrul reprezentand securitatea
	int lambda = 4;

	int gamma = (int)pow(lambda, 3);	// gamma = O(lambda^5)
	int eta = (int)pow(lambda, 1.5);	// eta = O(lamda^2)
	int ro = lambda; 
	int ro_prim = 2 * lambda;
	int tau = gamma + lambda;

	Params::set_params(gamma, eta, ro, tau, ro_prim);

	ZZ sk;
	vector<ZZ> pk;
	ZZ c;

	generate_keys(sk, pk);

	/***************************************************************/

	for (int i = 0; i < 100; i++)
	{
		// int i = 1;
		ZZ message(i);

		message = i % 2;

		c = encrypt_integer(pk, message);

		ZZ miu = decrypt_ciphertext(c, sk);

		if (message != miu)
		{
			cout << "Eroare la iteratia " << i << ", m = " << message
				<< ", miu = " << miu << endl;
		}
		else
		{
			cout << "Iteratia = " << i << " trecuta cu succes.\n";
		}
	}


	cout << "Test incheiat\n";
}

void test_gsw_scheme()
{
	int lambda = 5;
	int L = 5;

	GSWParams gswParams(lambda, L);


	// afisare parametrii
	cout << "q = " << gswParams.get_q() << endl;
	cout << "log_q = " << gswParams.get_log_q() << endl;
	/*cout << "n = " << gswParams.get_n() << endl;
	cout << "m = " << gswParams.get_m() << endl;
	cout << "setup_completed = " << gswParams.get_setup_state() << endl;

	cout << "____________________________________________________";
	cout << "\nTestare distributie chi\n";
	vector<ZZ> chi_vec = gswParams.sampleFromChiDistribution();

	cout << "chi_vec.size = " << chi_vec.size() << endl;
	for (int i = 0; i < chi_vec.size(); i++)
	{
		cout << "v[" << i << "] = " << chi_vec[i] << endl;
	}
	cout << "____________________________________________________";*/

	vector<ZZ> t;
	vector<ZZ> sk;
	vector<ZZ> v;

	SecretKeyGen(gswParams, t, sk, v);
	gswParams.set_v(v);

	vector<vector<ZZ> > A;
	PublicKeyGen(gswParams, t, A);

	int message = 0;
	int miu = 1;
	vector<vector<ZZ> > C;

	C = Enc(gswParams, A, message);
	miu = Dec(gswParams, sk, C);

	if (message != miu)
	{
		cout << "Eroare la decriptare.\n";
	}
	else
	{
		cout << "Decriptare CORECTA.\n";
	}


	cout << "Fini avec TEST_GSW\n";

}

void test_gsw_depth()
{
	// lambda - paramentrul reprezentand securitatea
	int lambda = 4;

	int gamma = (int)pow(lambda, 3);	// gamma = O(lambda^5)
	int eta = (int)pow(lambda, 1.5);	// eta = O(lamda^2)
	int ro = lambda;
	int ro_prim = 2 * lambda;
	int tau = gamma + lambda;

	Params::set_params(gamma, eta, ro, tau, ro_prim);

	ZZ sk;
	vector<ZZ> pk;
	ZZ c;

	long x_0;
	long enc_0;

	generate_keys(sk, pk);
	c = encrypt_integer(pk, ZZ(0));
	conv(x_0, pk[0]);
	conv(enc_0, c);

	BatchGSW batchGSW(x_0, enc_0);

	int **C = NULL;
	int message = 1;
	long dghv_ctxt = 0;
	long dghv_sk = 0;
	int miu = -1;

	conv(dghv_sk, sk);

	// testare operatii F-DGHV
	int **C1 = NULL;
	int **C2 = NULL;
	int **C_Eval = NULL;
	int **C_Mult = NULL;

	int ***to_be_freed = new int**[100];
	int capacity = 0;

	int m1 = -1;
	int m2 = -1;
	int m_eval = -1;
	int l = batchGSW.get_l();

	// m1 = rand() % 2;
	// m2 = rand() % 2;
	// m1 = m2 = 1;
	m1 = 1;
	m2 = 0;
	C1 = batchGSW.GSW_Encrypt(m1);
	C2 = batchGSW.GSW_Encrypt(m2);

	srand(time(NULL));
	for (int i = 0; i < 100; i++)
	{
		/*C_Eval = batchGSW.Flatten(matrix_add(C1, C2, l), l);

		dghv_ctxt = batchGSW.GSW_Decrypt(C_Eval);

		if (((m1 + m2) % 2) != (dghv_ctxt % dghv_sk % 2))
		{
			cout << "HE.Add : eroare la iteratia " << i << endl;
		}*/

		to_be_freed[capacity++] = C1;

		C1 = batchGSW.Flatten(matrix_mult(C1, C2, l), l);

		/*if ((m1*m2) != (dghv_ctxt % dghv_sk % 2))
		{
			cout << "HE.Mult : eroare la iteratia " << i << endl;
		}*/
	}

	dghv_ctxt = batchGSW.GSW_Decrypt(C1);

	if (dghv_ctxt % dghv_sk % 2 == 0)
	{
		cout << "EVALUARE CORECTA\n";
	}
	else
	{
		cout << "EROARE LA EVALUARE\n";
	}

	for (int i = 0; i < capacity; i++)
	{
		delete[] to_be_freed[i];
	}

	for (int i = 0; i < l; i++)
	{
		delete[] C1[i];
		delete[] C2[i];
		// delete[] C_Eval[i];
		// delete[] C_Mult[i];
	}
	delete[] C1;
	delete[] C2;
	delete[] to_be_freed;
	// delete[] C_Eval;
	// delete[] C_Mult;

	cout << "Final test_gsw_depth\n\n";
}

void test_batching_gsw()
{
	// lambda - paramentrul reprezentand securitatea
	int lambda = 4;

	int gamma = (int)pow(lambda, 3);	// gamma = O(lambda^5)
	int eta = (int)pow(lambda, 1.5);	// eta = O(lamda^2)
	int ro = lambda;
	int ro_prim = 2 * lambda;
	int tau = gamma + lambda;

	Params::set_params(gamma, eta, ro, tau, ro_prim);

	ZZ sk;
	vector<ZZ> pk;
	ZZ c;

	long x_0;
	long enc_0;

	generate_keys(sk, pk);
	c = encrypt_integer(pk, ZZ(0));
	conv(x_0, pk[0]);
	conv(enc_0, c);

#ifdef _TEST
	x_0 = 30;
	enc_0 = 22;
	// cout << "x_0 = " << x_0 << endl;
	// cout << "enc_0 = " << enc_0 << endl
#endif // _TEST
	
	BatchGSW batchGSW(x_0, enc_0);

	int **C = NULL;
	int message = 1;
	long dghv_ctxt = 0;
	long dghv_sk = 0;
	int miu = -1;

	conv(dghv_sk, sk);

	// testare operatii F-DGHV
	int **C1 = NULL;
	int **C2 = NULL;
	int **C_Eval = NULL;
	int **C_Mult = NULL;
	int m1 = -1;
	int m2 = -1;
	int m_eval = -1;
	int l = batchGSW.get_l();

	srand(time(NULL));
	for (int i = 0; i < 200; i++)
	{
		m1 = rand() % 2;
		m2 = rand() % 2;

		C1 = batchGSW.GSW_Encrypt(m1);
		C2 = batchGSW.GSW_Encrypt(m2);

		// C_Eval = batchGSW.Flatten(matrix_mult(C1, C2, l), l);
		C_Eval = batchGSW.Flatten(matrix_add(C1, C2, l), l);

		dghv_ctxt = batchGSW.GSW_Decrypt(C_Eval);

		if ( ((m1+m2)%2) != (dghv_ctxt % dghv_sk % 2))
		{
			cout << "HE.Add : eroare la iteratia " << i << endl;
		}
		// cout << m1 << " * " << m2 << " = " << dghv_ctxt % dghv_sk % 2 << endl;

		C_Mult= batchGSW.Flatten(matrix_mult(C1, C2, l), l);

		dghv_ctxt = batchGSW.GSW_Decrypt(C_Mult);

		if ((m1*m2)!= (dghv_ctxt % dghv_sk % 2))
		{
			cout << "HE.Mult : eroare la iteratia " << i << endl;
		}
	}

	for (int i = 0; i < l; i++)
	{
		delete[] C1[i];
		delete[] C2[i];
		delete[] C_Eval[i];
		delete[] C_Mult[i];
	}
	delete[] C1;
	delete[] C2;
	delete[] C_Eval;
	delete[] C_Mult;

	// testare criptare/decriptare F-DGHV
	/*for (int i = 0; i < 10; i++)
	{
		message = rand() % 2;
		// cout << "mesaj : " << message << endl;
		C = batchGSW.GSW_Encrypt(message);
		dghv_ctxt = batchGSW.GSW_Decrypt(C);
		miu = dghv_ctxt % dghv_sk % 2;
		// cout << "miu : " << miu << endl;
		if (message != miu)
		{
			cout << "Eroare la iteratia " << i << endl;
		}
	}*/

	cout << "Final teste F-DGHV\n\n";

}

int main()
{
	// test_DGHV_scheme();
	
	// test_gsw_scheme();

	// test_batching_gsw();

	test_gsw_depth();
}





// testare Flattening
/*
int *A[6];
for (int i = 0; i < 6; i++)
{
A[i] = new int[6];
for (int j = 0; j < 6; j++)
{
A[i][j] = 1;
}
A[i][i] = 1;
}

C = batchGSW.Flatten(A, 6);

for (int i = 0; i < 6; i++)
{
for (int j = 0; j < 6; j++)
{
cout << C[i][j] << " ";
}
cout << endl;

delete[] A[i];
delete[] C[i];
}
delete[] C;

cout << endl;*/