#include "palisade.h"
#include <iostream>
#include <chrono>
#include <vector>
#include <unistd.h>
 
using namespace std;
using namespace lbcrypto;
 
int main()
{	
	cout.precision(6);
    cout<<fixed;
 
    //PARAMETERS
    //const PlaintextModulus p = 65537;
    //double sigma = 3.2;
    uint32_t multiplicativeDepth = 1;
	uint32_t scalingFactorBits = 32;
    uint32_t batchSize = 8;
    SecurityLevel securityLevel = HEStd_128_classic;
    //int maxDepth = 2;
    CryptoContext<DCRTPoly> cc = 
		CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
			multiplicativeDepth, 
			scalingFactorBits, 
			batchSize, 
			securityLevel);
 	cc->Enable(ENCRYPTION);
 	cc->Enable(SHE);
 	
 	auto keys = cc->KeyGen();
 	cc->EvalMultKeyGen(keys.secretKey);
 	cc->EvalAtIndexKeyGen(keys.secretKey, {1, -2});
 	
 	//Dataset example
 	vector<double> x1 = {0.25,0.5,0.75,1.0,2.0,3.0,4.0,5.0};
 	vector<double> x2 = {5.0,4.0,3.0,2.0,1.0,0.75,0.5,0.25};
 	
 	Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
 	Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2);
 	
 	cout <<"Input x1:"<<ptxt1<<endl;
 	cout <<"Input x2:"<<ptxt2<<endl;
 	
 	auto start = chrono::steady_clock::now();
 	
 	auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
 	auto c2 = cc->Encrypt(keys.publicKey, ptxt2);
 	
 	Plaintext resultAdd;
 	
 	//EVALUATIONS ADD/MUL
 	
 	//EXPERIMENT no.1 - 10 cumulative ADD

 	auto cAdd = cc->EvalAdd(c1,c2);

	cc->Decrypt(keys.secretKey, cAdd, &resultAdd);
 	resultAdd->SetLength(batchSize);
 	 	
 	vector<double> dataVector = resultAdd->GetRealPackedValue();
 	vector<double> dataVector2 = resultAdd->GetRealPackedValue();
 	
 	cout<<"ITERATION: 1"<<endl;
 	cout<<"x1+x2 "<<resultAdd<<endl;
 	cout<<"Noise: ";
 	for(int i = 0; i<static_cast<int>(x1.size());i++)
 	{
  		dataVector2[i]=abs(dataVector[i]-(x1[i]+x2[i]));
  		cout<<dataVector2[i]<<", ";
  	}
  	cout<<endl<<endl;
 	for(int i = 1; i<=9 ;i++)
 	{	
	 	cout<<"ITERATION: "<<i+1<<endl;
 		cAdd = cc->EvalAdd(cAdd,cAdd);	
 		cc->Decrypt(keys.secretKey, cAdd, &resultAdd);
	 	resultAdd->SetLength(batchSize);
	 	dataVector = resultAdd->GetRealPackedValue();
	 	cout<<fixed;
	 	cout<<"x1+x2 "<<resultAdd<<endl;
	 	cout<<"Noise: ";
	 	for(int j = 0; i<static_cast<int>(x1.size());i++)
 		{
  			cout<<abs(dataVector[j]-dataVector2[j]);
  		}
	 	
	}
    auto end = chrono::steady_clock::now();
 
    cout << "Elapsed time in nanoseconds: "
        << chrono::duration_cast<chrono::nanoseconds>(end - start).count()
        << " ns" << endl;
 
    cout << "Elapsed time in microseconds: "
        << chrono::duration_cast<chrono::microseconds>(end - start).count()
        << " µs" << endl;
 
    cout << "Elapsed time in milliseconds: "
        << chrono::duration_cast<chrono::milliseconds>(end - start).count()
        << " ms" << endl;
 
    cout << "Elapsed time in seconds: "
        << chrono::duration_cast<chrono::seconds>(end - start).count()
        << " sec";
        
         	/*
         	//EXPERIMENT no.2 - 10 cumulative ADD
         	//EXPERIMENT no.3 - 10 cumulative MUL
         	//EXPERIMENT no.4 - 10 cumulative PARAM SET 2
         	//EXPERIMENT no.5 - 10 cumulative PARAM SET 3
 	cc->Decrypt(keys.secretKey,cSub,&result);
 	result->SetLength(batchSize);
 	cout<<"x1-x2 "<<result<<endl;
 	
 	cc->Decrypt(keys.secretKey,cScalar,&result);
 	result->SetLength(batchSize);
 	cout<<"x1*4 "<<result<<endl;
 	
 	cc->Decrypt(keys.secretKey,cMul,&result);
 	result->SetLength(batchSize);
 	cout<<"x1*x2 "<<result<<endl;
 	
 	cc->Decrypt(keys.secretKey,cRot1,&result);
 	result->SetLength(batchSize);
 	cout<<"x1 Rot1 x2 "<<result<<endl;
 	
 	cc->Decrypt(keys.secretKey,cRot2,&result);
 	result->SetLength(batchSize);
 	cout<<"x1 Rot 2 x2 "<<result<<endl;
 	
 	*/
 	
    return 0;
}
