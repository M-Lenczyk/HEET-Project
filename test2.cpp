#include "palisade.h"
#include "utils.cpp"
#include "cryptocontextgen.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <thread>
#include <vector>

#include <limits>
#include <ctime>
#include <cstdlib>

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
   		this->maxDepth = 8;//3
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
	int num_experiments = 10;

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
	
  	std::cout<<"Key generation time for homomorphic multiplication evaluation keys: "<<processingTime<<"ms"<<std::endl;
	

    int64_t num_pixels = 5;
    std::vector<int64_t> dataset;
    

	for(int64_t i=0;i<num_pixels;i++)
    {
		int64_t max =  123456;//std::numeric_limits<int32_t>::max();
		//int64_t max = 107387000;
        dataset.push_back(max-i);
    }

    //std::vector<int64_t> addition_dataset(dataset.size(), 20);
	std::vector<int64_t> addition_dataset;

	for(int i=0;i<(int)dataset.size();i++)
	{
		addition_dataset.push_back((int64_t)rand()%2+1);
	}

	std::vector<std::shared_ptr<std::vector<int64_t>>> predicted_results;

	std::cout<<"size: "<<(int)dataset.size()<<std::endl;
	predicted_results.push_back(sum_of_vectors(dataset,addition_dataset));

	for(int i=1;i<num_experiments;i++)
	{
		predicted_results.push_back(sum_of_vectors(*(predicted_results[i-1]) , addition_dataset));
	}

    vector<Plaintext> plaintextDatasetVector;
    vector<Plaintext> addPlaintextDatasetVector;

	plaintextDatasetVector.push_back(cryptoContext->MakePackedPlaintext(dataset));
	addPlaintextDatasetVector.push_back(cryptoContext->MakePackedPlaintext(addition_dataset));


    vector<Ciphertext<DCRTPoly>> ciphertexts;
    vector<Ciphertext<DCRTPoly>> addCiphertexts;

	ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintextDatasetVector[0]));
	addCiphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, addPlaintextDatasetVector[0]));


    std::vector<Ciphertext<DCRTPoly>> results;
	std::vector<std::vector<int64_t>> decryptedResults;

	auto vector_after_addition = cryptoContext->EvalMult(ciphertexts[0], addCiphertexts[0]);
	//auto vector_after_subtraction = cryptoContext->EvalSub(vector_after_addition, addCiphertexts[0]);	
	results.push_back(vector_after_addition);

    
    for(int i=1;i<num_experiments;i++)
    {
		std::cout<<"test:"<<i<<std::endl;
		vector_after_addition = cryptoContext->EvalMult(vector_after_addition, addCiphertexts[0]);
		//vector_after_subtraction = cryptoContext->EvalSub(vector_after_addition, addCiphertexts[0]);
		results.push_back(vector_after_addition);
    }
	std::cout<<"size size encrypted: "<<results.size()<<std::endl;

	for(auto &cipher : results)
	{
		decryptedResults.push_back(decrypt(t, cryptoContext, keyPair, cipher, plaintextDatasetVector)->GetPackedValue());
	}
	std::cout<<"size decry: "<<decryptedResults.size()<<std::endl;

	auto input_vector = plaintextDatasetVector[0]->GetPackedValue();

	std::cout<<"size pred: "<<predicted_results.size()<<std::endl;
	

	std::cout<<"-----------------ORIG----------------"<<std::endl;
	print_vector(dataset);
	std::cout<<"---------------------------------"<<std::endl;

	for(int i = 0; i < num_experiments-1; i++)
	{
		std::cout<<"iteration: "<<i<<std::endl;
		print_vector(*(predicted_results[i]));
		std::cout<<"+";print_vector(addition_dataset);
		print_vector(decryptedResults[i]);
		std::cout<<"---------------------------------"<<std::endl;
		std::cout<<vector_statistic_combined(*(predicted_results[i]),decryptedResults[i]).to_string();
		std::cout<<"---------------------------------"<<std::endl;
	}		
}

uint64_t modulusPicker(uint64_t approxDesiredModulus = 536903681, uint64_t cyclotomicOrder = 65536, bool debug=0)
	{	
		//Rozmiar modulusa w bitach. Na przykład: 
		//dla modulusa = 15 mamu: ceil(log2(15)) = ceil(3.9) = 4 
		//dla modulusa = 16 mamy ceil(log2(16)) = ceil(4.0) = 4 
		//dla modulusa = 17 mamy ceil(log2(17)) = ceil(4.08) = 5
		unsigned short bits = ceil(log2(approxDesiredModulus));
		
		//Wybór pierwszej liczby pierwszego która spełnia nasze kryteria i wymagania PALISADE
		//To jest nasz rzeczywisty modulus
    	auto viablePrime = FirstPrime<NativeInteger>(bits-1, 2*cyclotomicOrder);
    	
    	//Konwersja wybranego modulusa do formatu akceptowanego przez zestaw parametrów
    	uint64_t plaintextModulus = reinterpret_cast<uint64_t &>(viablePrime);
    	
    	if(debug)
    	{
    		std::cout<<"Desired modulus: "<<approxDesiredModulus<<std::endl;
	    	std::cout<<"Number of bits: "<<bits<<std::endl;
	    	std::cout<<"Satisfactory prime: "<<viablePrime<<" Type: "<<typeid(viablePrime).name()<<std::endl;
	    	std::cout<<"Respective modulus: "<<plaintextModulus<<" Type: "<<typeid(plaintextModulus).name()<<std::endl;
		}
    	return plaintextModulus;
	}

int main() 
{
	std::cout<<"VECTOR COMPARISON TEST"<<std::endl;
	srand(time(NULL));
	parameterBlock p1(modulusPicker(1073870000000), HEStd_128_classic, 3.2, 10);

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
	return 0;
}