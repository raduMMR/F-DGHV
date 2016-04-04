#include "utilities.h"
#include "gsw.h"

void test_DGHV_scheme()
{
	// lambda - paramentrul reprezentand securitatea
	int lambda = 4;

	int gamma = pow(lambda, 3);	// gamma = O(lambda^5)
	int eta = pow(lambda, 1.5);	// eta = O(lamda^2)
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
	}


	cout << "Test incheiat\n";
}

void test_gsw_scheme()
{

}

int main()
{
	test_DGHV_scheme();

	// test_gsw_scheme();
}