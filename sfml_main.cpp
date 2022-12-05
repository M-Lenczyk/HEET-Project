#include "palisade.h"
#include "utils.cpp"
#include "cryptocontextgen.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <thread>
#include <vector>

#include <bits/stdc++.h>

#include <SFML/Graphics.hpp>



struct parameterBlock
{	
	//Te parametry beda zmieniane

    PlaintextModulus plaintextModulus; //Plaintextmodulus - w naszym przypadku (integers) maksymalna granica obliczeń - The bound for integer arithmetic
    SecurityLevel securityLevel;//Poziom zabezpieczeń, inaczej trudność złamania bez znajomości klucza. Np. Dla HE128 oznacza to 2^128 operacji przy najlepszej metodzie ataku.
    float dist;//W innych metodach pod nazwą stdDev. Odchylenie standardowe. Używany do generowania szumu gaussowskiego. Standardowo 3.2, 3.4 Distribution parameter for Gaussian noise generation 
    unsigned int numMults;//Maksymalna 'głębokość' operacji mnożeń. Nie jest to liczba mnożeń. Np. dla x1*x2*x3*x4 numMults = 1, natomiast dla (((x1*x2)*x3)*x4) numMults wynosi już 4. Multiplicative depth for homomorphic computations (assumes numAdds and numKeySwitches are set to zero)
    
    //Tych parametrow raczej ruszac nie bedziemy i beda wartosci domyslne
    unsigned int numAdds;//Analogicznie jak w przypadku numMults. Additive depth for homomorphic computations (assumes numMults and numKeySwitches are set to zero) 
    unsigned int numKeyswitches;//key-switching depth for homomorphic computations (assumes numAdds and numMults are set to zero)
    MODE mode;//secret key distribution mode (RLWE [Gaussian noise] or OPTIMIZED [ternary uniform distribution]) 
    int maxDepth;//the maximum power of secret key for which the relinearization key is generated (by default, it is 2); setting it to a value larger than 2 adds support for homomorphic multiplication w/o relinearization 
    uint32_t relinWindow;//the key switching window (bits in the base for digits) used for digit decomposition (0 - means to use only CRT decomposition) 
    size_t dcrtBits;//size of "small" CRT moduli 
    uint32_t n;//ring dimension in case the user wants to use a custom ring dimension 
	
	//FULL CONSTRUCTOR
	/*
    parameterBlock(	PlaintextModulus _plaintextModulus = 65537,
					SecurityLevel _securityLevel = HEStd_128_classic,
					float _dist = 3.2,
					unsigned int _numAdds = 0,
					unsigned int _numMults = 2,
					unsigned int _numKeyswitches = 0,
					MODE _mode = OPTIMIZED,
					int _maxDepth = 2,
					uint32_t _relinWindow = 0,
					size_t _dcrtBits = 60,
					 uint32_t _n = 0)
    {
    	this->plaintextModulus = _plaintextModulus;
    	this->securityLevel = _securityLevel;
    	this->dist = _dist;
   		this->numAdds = _numAdds;
   		this->numMults = _numMults;
   		this->numKeyswitches = _numKeyswitches;
    	this->mode = _mode;
   		this->maxDepth = _maxDepth;
   		this->relinWindow = _relinWindow;
    	this->dcrtBits = _dcrtBits;
    	this->n = _n;
	}
	*/
	
	//SHORT CONSTRUCTOR
	parameterBlock( PlaintextModulus _plaintextModulus, 
					SecurityLevel _securityLevel,
					float _dist,
					unsigned int _numMults)
	{
		this->plaintextModulus = _plaintextModulus;
    	this->securityLevel = _securityLevel;
    	this->dist = _dist;
   		this->numAdds = 0;
   		this->numMults = _numMults;//3
   		this->numKeyswitches = 0;
    	this->mode = OPTIMIZED;
   		this->maxDepth = 3;//3
   		this->relinWindow = 0;
    	this->dcrtBits = 60;
    	this->n = 0;
	}
    
};
//Funkcja pomocnicza do wyświetlania w konsoli w przypadku wielu zestawu parametrów
void breaker(unsigned short int variant)
{	
	vector<std::string> variantCheatSheet =
	{
		"10 x ADD",
		"10 x MUL",
		"5x ADD + 5x MUL",
		"5x MUL + 5x ADD",
		"2x ADD + 7x MUL + 1x ADD",
		"1x MUL + 9x ADD",
		"1x ADD + 9x MUL",
		"1x ADD + 1x MULL + 1x ADD + 1x MULL ... total 10x",
		"3x ADD + 3x MUL + 4x ADD",
		"2x MUL + 5x ADD + 1x MUL + 2x ADD"	
	};
	std::cout<<std::endl;
	std::cout<<"-------------------------VARIANT "<<variant<<": "<<variantCheatSheet[variant-1]<<"-------------------------"<<std::endl;
}

template <typename T>
Plaintext decrypt(TimeVar &t,
			CryptoContext<DCRTPoly> &cryptoContext,
 			LPKeyPair<DCRTPoly> &keyPair,
 			Ciphertext<T> &ciphertextResult,
  			vector<Plaintext> &plaintextDatasetVector)
{
	Plaintext plaintextResult;//Zmienna wynikowa plaintext do odczytu
	TIC(t);//Moment rozpoczecia mierzenia czasu deszyfracji
	//Deszyfracja ciphertextResult na podstawie klucza w odniesieniu do cryptocontextu i zapisanie do plaintextResult
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextResult);
	TOC(t);
	//Ustawienie dlugosci wyswietlania wyniku na podstawie batchSize.
	plaintextResult->SetLength(plaintextDatasetVector[0]->GetLength());
	return plaintextResult;
}

//Funkcja główna do przeprowadzania pojedynczego eksperymentu na datasecie, zestawie parametrów i wybranego wariantu operacji homomorficznych
void experiment(parameterBlock p1, std::vector<std::vector<int64_t>> datasetVector, unsigned short int variant)
{
	TimeVar t; //Obiekt ktory bedzie zliczal czas.
  	double processingTime(0.0);//Zmienna ktora bedzie przechowywac czas zliczony przez obiekt t klasy TimeVar
  	
	//Tworzenie zestawu parametrów używanych do zakodowania samych plaintextów na podstawie naszego modulusa. 
	//Parametry te są obiektem/kontenerem encodingParams klasy EncodingParams.   
  	EncodingParams encodingParams(std::make_shared<EncodingParamsImpl>(p1.plaintextModulus));
	
	//MAIN. Główna funckja generująca nasz cryptoContext na podstawie naszych wybranych parametrów.
	//Wszystkie operacje homomorficzne, generowanie kluczy itd. odbywają się na jego podstawie.
	//Możemy sobie go wyobrazić jako pseudowrapper.
	
	//CryptoContext realizuje operacje na elementach: 
	//Poly - wskaźnikach wielomianu, 
	//NativePoly - wskaźnikach wielomianu typu 64bit integer 
	//DCRTPoly - który przyjmuje jeden wielki wielomian i rozbija go na zestaw elementów NativePoly.  
	CryptoContext<DCRTPoly> cryptoContext =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          encodingParams, p1.securityLevel, p1.dist, p1.numAdds, p1.numMults, p1.numKeyswitches, p1.mode, p1.maxDepth);


	//Włączenie ficzerków PALISADE które chcemy wykorzystać
    cryptoContext->Enable(ENCRYPTION);//Szyfracja deszyfracja. Duh
	cryptoContext->Enable(SHE);//Somewhat Homomorphic Encryption - ograniczamy liczbe operacji do zadanego poziomu (depth)
	
	//Wyswietlanie uzytych parametrow i wariantu testu
	breaker(variant);
	std::cout << "\nParameters used: "<<std::endl;
	std::cout << "\nPlaintext modulus: "<<cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
	std::cout << "\nSecurity Level: "<<p1.securityLevel;
	std::cout << "\nDistribution (Gauss): "<<p1.dist;
	std::cout << "\nDepth (numMults): "<<p1.numMults;
	std::cout << std::endl;
	
	// Initialize Public Key Containers
	LPKeyPair<DCRTPoly> keyPair;
	
	//GENEROWANIE KLUCZY ŹRÓDŁOWYCH
	
	TIC(t);//Moment rozpoczecia mierzenia czasu.
	keyPair = cryptoContext->KeyGen();//Generacja pary kluczy do szyfrowania naszych danych które będą w formacie plaintext
	processingTime = TOC(t);//Moment zakonczenia mierzenia czasu i przypisania do zmiennej. Czas dla obiektu t jest zresetowany automatycznie.
  	std::cout<<"\nSource key generation time: " <<processingTime<<"ms"<<std::endl;
	
	//GENEROWANIE KLUCZY DLA MNOZENIA HOMOMORFICZNEGO
	TIC(t);//Moment rozpoczecia mierzenia czasu.
	cryptoContext->EvalMultKeysGen(keyPair.secretKey);//Generowanie kluczy wymaganych do operacji mnozenia homomorficznego na podstawie klucza danych źródłowych.
	processingTime = TOC(t);//Moment zakończenia mierzenia czasu.
  	std::cout<<"Key generation time for homomorphic multiplication evaluation keys: "<<processingTime<<"ms";
	
    int num_pixels = 256;
    std::vector<int64_t> dataset;
    

	for(int i=0;i<num_pixels;i++)
    {
        dataset.push_back(i%256);
        dataset.push_back(i%256);
        dataset.push_back(i%256);
    }

    std::vector<int64_t> addition_dataset(dataset.size(), 20);

    vector<Plaintext> plaintextDatasetVector;
    vector<Plaintext> addPlaintextDatasetVector;

	plaintextDatasetVector.push_back(cryptoContext->MakePackedPlaintext(dataset));
	addPlaintextDatasetVector.push_back(cryptoContext->MakePackedPlaintext(addition_dataset));


    vector<Ciphertext<DCRTPoly>> ciphertexts;
    vector<Ciphertext<DCRTPoly>> addCiphertexts;

	ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintextDatasetVector[0]));
	addCiphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, addPlaintextDatasetVector[0]));

    
    //std::vector<auto> storedVectors();
	std::vector<float> operations = {0.5};

    std::vector<Ciphertext<DCRTPoly>> results;
	std::vector<std::vector<int64_t>> decryptedResults;

    int num_experiments = 10000;
    for(int i=0;i<num_experiments;i++)
    {
		std::cout<<"test:"<<i<<std::endl;
		auto vector_after_addition = cryptoContext->EvalAdd(ciphertexts[0], addCiphertexts[0]);
		results.push_back(cryptoContext->EvalSub(vector_after_addition, addCiphertexts[0]));
    }

	for(auto &cipher : results)
	{
		decryptedResults.push_back(decrypt(t, cryptoContext, keyPair, cipher, plaintextDatasetVector)->GetPackedValue());
	}

	auto input_vector = plaintextDatasetVector[0]->GetPackedValue();

	for(int i = num_experiments-10; i < num_experiments; i++)
	{
		std::cout<<vector_statistic_combined(input_vector,decryptedResults[i]).to_string();
	}		
}

int main() 
{
	parameterBlock p1(536903681, HEStd_128_classic, 3.2, 3);
	
	parameterBlock p2(375049, HEStd_128_classic, 3.2, 3);
	parameterBlock p3(10002191, HEStd_128_classic, 3.2, 3);
	parameterBlock p4(75005101, HEStd_128_classic, 3.2, 3);
	parameterBlock p5(9750005347, HEStd_128_classic, 3.2, 3);
	
	parameterBlock p6(375049, HEStd_128_classic, 3.2, 3);
	parameterBlock p7(536903681, HEStd_192_classic, 3.2, 3);
	parameterBlock p8(375049, HEStd_192_classic, 3.2, 3);
	parameterBlock p9(536903681, HEStd_256_classic, 3.2, 3);
	parameterBlock p10(375049, HEStd_256_classic, 3.2, 3);
	
	parameterBlock p11(536903681, HEStd_128_classic, 0.2, 3);
	parameterBlock p12(536903681, HEStd_128_classic, 6.4, 3);
	parameterBlock p13(536903681, HEStd_128_classic, 20.4, 3);
	parameterBlock p14(536903681, HEStd_128_classic, 100.8, 3);
	parameterBlock p15(536903681, HEStd_128_classic, 0.0001, 3);
	
	parameterBlock p16(536903681, HEStd_128_classic, 3.2, 1);
	parameterBlock p17(536903681, HEStd_128_classic, 3.2, 2);
	parameterBlock p18(536903681, HEStd_128_classic, 3.2, 9);
	parameterBlock p19(536903681, HEStd_128_classic, 3.2, 20);
	parameterBlock p20(536903681, HEStd_128_classic, 3.2, 50);
	
	//TWORZENIE DATASETU - 10 wektorów o rozmiarze vectorSize, wypełniony liczbami od 1 do UpperBound
	unsigned int vectorSize = 10;
	unsigned long int genUpperBound = 10;//Gorna granica dla generatora liczb losowych
	std::vector<std::vector<int64_t>> datasetVector;//Kontener dla calego datasetu
	for(unsigned int i = 0; i<vectorSize; i++)
	{	
		std::vector<int64_t> v(vectorSize,0);//Tworzenie pojedynczego wektora
		srand(time(0));
		generate(v.begin(), v.end(), RandomNumberBetween(1,genUpperBound));//Wypelnienie pojedynczego wektora z uzyciem generatora liczb losowych 'RandomNumberBetwen'
		datasetVector.push_back(v);//Zapis do kontenera
	}
	
	//VARIANT CHEATSHEET
	//1. 10 x ADD
	//2. 10 x MUL
	//3. 5x ADD + 5x MUL
	//4. 5x MUL + 5x ADD
	//5. 2x ADD + 7x MUL + 1x ADD"
	//6. 1x MUL + 9x ADD
	//7. 1x ADD + 9x MUL
	//8. 1x ADD + 1x MULL + 1x ADD + 1x MULL ... total 10x
	//9. 3x ADD + 3x MUL + 4x ADD
	//10. 2x MUL + 5x ADD + 1x MUL + 2x ADD
	
	unsigned short int variant=10;//Wybrany wariant testu
	experiment(p1,datasetVector,variant);
	//TODO: ... more experiments
}