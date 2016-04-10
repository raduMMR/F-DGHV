#include "utilities.h"
#include "gsw.h"
#include "BatchGSW.h"
#include <time.h>
#include <assert.h>
#include "Flat_DGHV.h"

// TODO : IMPLEMENTAREA SCHEMEI PE BAZA NTL
// DGHV securiy parameter
// dupa Fully homomorphic encryption over the Integers with Shorter Public Key by Coron et.al
// http://publications.uni.lu/bitstream/10993/12396/1/441.pdf
// valoare acceptata pentru x_0 si enc_0 reprezentati ca long
// #define SEC_PARAM 42		// toy 
// #define SEC_PARAM 52		// small
// #define SEC_PARAM 62		// medium 
// #define SEC_PARAM 72		// large

#define SEC_PARAM 6 
#define NR_TESTE 100
#define MULT_DEPTH 50

void test_DGHV_scheme()
{
	// lambda - paramentrul reprezentand securitatea
	int lambda = SEC_PARAM;

	int gamma = (int)pow(lambda, 3);	// gamma = O(lambda^5)
	int eta = (int)pow(lambda, 1.5);	// eta = O(lamda^2)
	int ro = lambda; 
	int ro_prim = 2 * lambda;
	int tau = gamma + lambda;

	/*cout << "lambda = " << lambda << endl;
	cout << "gamma = " << gamma << endl;
	cout << "eta = " << eta << endl;
	cout << "ro = " << ro << endl;
	cout << "ro_prim  = " << ro_prim << endl;
	cout << "tau = " << tau << endl;*/

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
	cout << "\n\ntest_gsw_depth\n\n";

	// lambda - paramentrul reprezentand securitatea
	int lambda = SEC_PARAM;

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

	int ***to_be_freed = new int**[MULT_DEPTH];
	int capacity = 0;

	int m1 = -1;
	int m2 = -1;
	int m_eval = -1;
	int l = batchGSW.get_l();

	m1 = 0;
	m2 = 1;
	C1 = batchGSW.GSW_Encrypt(m1);
	C2 = batchGSW.GSW_Encrypt(m2);

	srand(time(NULL));
	for (int i = 0; i < MULT_DEPTH; i++)
	{
		to_be_freed[capacity++] = C1;

		C1 = batchGSW.Flatten_mod_x_0(batchGSW.matrix_mult(C1, C2, l), l);
	}

	dghv_ctxt = batchGSW.GSW_Decrypt(C1);

	if ( (dghv_ctxt % dghv_sk % 2) == (m1*m2) )
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
	}
	delete[] C1;
	delete[] C2;
	delete[] to_be_freed;

	cout << "Final test_gsw_depth\n\n";
}

void test_DGHV_max_depth()
{
	cout << "Testing DGHV scheme max depth ...\n";
	int lambda = SEC_PARAM;
	int gamma = (int)pow(lambda, 5);	
	int eta = (int)pow(lambda, 3);	
	int ro = lambda;
	int ro_prim = 2 * lambda;
	int tau = gamma + lambda;
	Params::set_params(gamma, eta, ro, tau, ro_prim);
	ZZ sk;
	vector<ZZ> pk;

	generate_keys(sk, pk);

	ZZ c1 = encrypt_integer(pk, ZZ(1));
	ZZ c2 = encrypt_integer(pk, ZZ(1));

	for (int i = 0; i < 200; i++)
	{
		c1 = c1*c2;
		ZZ miu = decrypt_ciphertext(c1, sk);

		if ( miu != ZZ(1) )
		{
			cout << "Max depth = " << i << endl;
			break;
		}
	}

	cout << "Test pentru max_DGHV_depth incheiat\n";
}

void clean_matrix(int **A, int l)
{
	assert(A != NULL);
	for (int i = 0; i < l; i++)
	{
		delete[] A[i];
	}
	delete[] A;
}

void test_F_DGHV()
{
	cout << "\n\n\t\tTestare F-DGHV\n\n";
	int **matrix_Collector = NULL;
	// setare schema DGHV
	int lambda = SEC_PARAM;
	int gamma = (int)pow(lambda, 5);
	int eta = (int)pow(lambda, 3);	
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
	long dghv_ctxt = 0;
	long dghv_sk = 0;
	conv(dghv_sk, sk);
	

	BatchGSW batchGSW(x_0, enc_0);

	// matrici F-DGHV
	int **C1 = NULL;
	int **C2 = NULL;
	int m1 = 1;
	int m2 = 1;

	int l = batchGSW.get_l();
	assert(l != 0);

	// int m_eval = m1 = rand() % 2;
	int m_eval = 1;

	C1 = batchGSW.GSW_Encrypt(m1);
	C2 = batchGSW.GSW_Encrypt(m2);

	srand(time(NULL));
	for (int i = 0; i < NR_TESTE; i++)
	{
		// m2 = rand() % 2;
		// C2 = batchGSW.GSW_Encrypt(m2);

		/*if (i % 2 == 0)
		{
			matrix_Collector = C1;
			C1 = batchGSW.Flatten_mod_x_0(batchGSW.matrix_add(C1, C2, l), l);
			m_eval += m2;

			dghv_ctxt = batchGSW.GSW_Decrypt(C1);

			if (((m_eval) % 2) != (dghv_ctxt % dghv_sk % 2))
			{
				cout << "HE.Add : eroare la iteratia " << i << endl;
			}

			clean_matrix(matrix_Collector, l);
		}
		else
		{*/

			matrix_Collector = C1;
			C1 = batchGSW.Flatten_mod_x_0(batchGSW.matrix_mult(C1, C2, l), l);
			//m_eval *= m2;

			dghv_ctxt = batchGSW.GSW_Decrypt(C1);

			clean_matrix(matrix_Collector, l);

			if (m_eval != ( dghv_ctxt % dghv_sk % 2 ) )
			{
				cout << "HE.Mult : eroare la iteratia " << i << endl;
				break;
			}
		//}

	}

	clean_matrix(C1, l);
	clean_matrix(C2, l);

	cout << "Final teste F-DGHV\n\n";

}

void test_batching_gsw()
{
	cout << "\n\ntest F-DGHV\n\n";

	// lambda - paramentrul reprezentand securitatea
	int lambda = SEC_PARAM;

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
	int m1 = -1;
	int m2 = -1;
	int m_eval = -1;
	int l = batchGSW.get_l();

	/*srand(time(NULL));
	for (int i = 0; i < 200; i++)
	{
		m1 = rand() % 2;
		m2 = rand() % 2;

		C1 = batchGSW.GSW_Encrypt(m1);
		C2 = batchGSW.GSW_Encrypt(m2);

		// C_Eval = batchGSW.Flatten(matrix_mult(C1, C2, l), l);
		C_Eval = batchGSW.Flatten(batchGSW.matrix_add(C1, C2, l), l);

		dghv_ctxt = batchGSW.GSW_Decrypt(C_Eval);

		if (((m1 + m2) % 2) != (dghv_ctxt % dghv_sk % 2))
		{
			cout << "HE.Add : eroare la iteratia " << i << endl;
		}
		// cout << m1 << " * " << m2 << " = " << dghv_ctxt % dghv_sk % 2 << endl;

		C_Mult = batchGSW.Flatten(batchGSW.matrix_mult(C1, C2, l), l);

		dghv_ctxt = batchGSW.GSW_Decrypt(C_Mult);

		if ((m1*m2) != (dghv_ctxt % dghv_sk % 2))
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
	delete[] C_Mult;*/

	cout << "Final teste F-DGHV\n\n";
}

/*
@brief aceasta metoda utilizeaza gresit schema gsw
	singura ratiune fiind de a verifica daca batching-ul
	pentru matricle gsw este posibil
*/
void naive_gsw()
{
	cout << "\n\tTestare BATCHING pentru matrici GSW\n\n";

	int lambda = SEC_PARAM;
	int gamma = (int)pow(lambda, 3);	
	int eta = (int)pow(lambda, 1.5);	
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
	long dghv_ctxt = 0;
	long dghv_sk = 0;
	conv(dghv_sk, sk);

	BatchGSW batchGSW(x_0, enc_0);

	int **C1 = NULL;
	int **C2 = NULL;
	int l_batch = batchGSW.get_l();

	int *vec1 = new int[l_batch];
	int *vec2 = new int[l_batch];
	int *v_mult = NULL;

	srand(time(NULL));
	for (int i = 0; i < l_batch; i++)
	{
		vec1[i] = rand() % 2;
		vec2[i] = rand() % 2;
	}

	C1 = batchGSW.batch_GSW_Enc(vec1);
	C2 = batchGSW.batch_GSW_Enc(vec2);

	for (int nr_test = 0; nr_test < NR_TESTE; nr_test++)
	{
		// cleanup vec2
		delete[] vec2;

		// genereaza vec2 nou
		vec2 = new int[l_batch];
		for (int i = 0; i < l_batch; i++)
		{
			vec2[i] = rand() % 2;
		}

		int **Cp = C2;
		// cripteaza noul vec2
		C2 = batchGSW.batch_GSW_Enc(vec2);

		// cleanup old C2
		for (int i = 0; i < l_batch; i++)
		{
			delete[] Cp[i];
		}
		delete[] Cp;

		// C1 = C1 * C2;		C1 = Flatten( C1 * C2 )
		Cp = C1;
		C1 = batchGSW.batch_Flatten_mod_x_0(
			batchGSW.matrix_mult(C1, C2, l_batch), l_batch);

		// cleanup old C1
		for (int i = 0; i < l_batch; i++)
		{
			delete[] Cp[i];
		}
		delete[] Cp;

		int *vp = v_mult;
		v_mult = batchGSW.batch_GSW_Dec(C1);

		//cleanup old v_mult
		delete[] vp;

		bool batch_ok = true;
		for (int i = 0; i < 1; i++)
		{
			if ( ( ( vec1[i] * vec2[i]) % 2) != ( v_mult[i] % dghv_sk % 2))
			{
				cout << "Eroare la batch iteratia " << nr_test << ", slot- ul " << i << "\n";
				batch_ok = false;
				break;
			}
		}
		if (batch_ok == true)
		{
			// cout << "Batch realizat cu SUCCES.\n";
			for (int ii = 0; ii < l_batch; ii++)
			{
				vec1[ii] = v_mult[ii];
			}
		}
		else
		{
			break;
		}

	}

	//cleanup batch
	if (v_mult != NULL)
		delete[] v_mult;
	delete[] vec1;
	delete[] vec2;
	for (int i = 0; i < l_batch; i++)
	{
		delete[] C1[i];
		delete[] C2[i];
	}
	delete[] C1;
	delete[] C2;

	cout << "Final - TEST BATCHING\n\n";
}

void test_Flat_DGHV()
{
	cout << "Testare Flat_DGHV ...\n\n";
	int lambda = 4;
	Flat_DGHV fdghv(lambda);

	Mat_ZZ C;

	for (int i = 0; i < NR_TESTE; i++)
	{
		int mesaj = rand() % 2;
		C = fdghv.encrypt(mesaj);

		if (mesaj == fdghv.decrypt(C))
		{
			// cout << "Succes\n";
		}
		else
		{
			cout << "Eroare i = "<<i<<endl;
		}

	}
	cout << "Final test Flat_DGHV\n";
}

int main()
{
	// test_DGHV_scheme();
	
	// test_gsw_scheme();

	// test_DGHV_max_depth();

	// test_F_DGHV();

	// test_batching_gsw();

	// test_gsw_depth();

	// naive_gsw();

	test_Flat_DGHV();
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