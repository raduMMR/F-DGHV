#include "utilities.h"
#include "gsw.h"
#include "BatchGSW.h"

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

	int **C;
	int message = 1;
	long dghv_ctxt = 0;
	long dghv_sk = 0;
	int miu = -1;

	conv(dghv_sk, sk);

	for (int i = 0; i < 10; i++)
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
	}

	cout << "Final teste F-DGHV\n\n";

}

int main()
{
	// test_DGHV_scheme();
	
	// test_gsw_scheme();

	test_batching_gsw();
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