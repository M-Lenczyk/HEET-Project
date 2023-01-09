#include "palisade.h"
#include "utils.cpp"
#include "cryptocontextgen.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <thread>
#include <vector>
#include <cmath>

//#include "cryptopp/modes.h"
//#include "cryptopp/aes.h"
//#include "cryptopp/filters.h"

#include <bits/stdc++.h>

//USED SCHEMA: BFVrns  - Brakerski-Fan-Vercauteren Residue Number System – breaks rings of large bit-width integers into a parallel set of rings using < 64 bit residues, allowing very efficient computation on 64-bit CPU architectures
//Key switching after multiplication is called relinearization

struct parameterBlock
{	
	//Te parametry beda zmieniane

    PlaintextModulus plaintextModulus; //Plaintextmodulus - w naszym przypadku (integers) maksymalna granica obliczeń - The bound for integer arithmetic
    SecurityLevel securityLevel;//Poziom zabezpieczeń, długość klucza - inaczej trudność złamania bez znajomości klucza. Np. Dla HE128 oznacza to 2^128 operacji przy najlepszej metodzie ataku.
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
void decrypt(TimeVar &t,CryptoContext<DCRTPoly> &cryptoContext,
 			LPKeyPair<DCRTPoly> &keyPair,
 			Ciphertext<T> &ciphertextResult,
  			vector<Plaintext> &plaintextDatasetVector,
			std::ofstream *resFile = nullptr)
{
	Plaintext plaintextResult;//Zmienna wynikowa plaintext do odczytu
	TIC(t);//Moment rozpoczecia mierzenia czasu deszyfracji
	//Deszyfracja ciphertextResult na podstawie klucza w odniesieniu do cryptocontextu i zapisanie do plaintextResult
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextResult);
	double processingTime = TOC(t);
	std::cout << "\nDecryption time: " << processingTime << "ms" << std::endl;
	if (resFile != nullptr) (*resFile) << processingTime << std::endl;
	//Ustawienie dlugosci wyswietlania wyniku na podstawie batchSize.
	plaintextResult->SetLength(plaintextDatasetVector[0]->GetLength());
	std::cout <<"\nDecryption result: "<< plaintextResult << std::endl;
}



//Funkcja główna do przeprowadzania pojedynczego eksperymentu na datasecie, zestawie parametrów i wybranego wariantu operacji homomorficznych
void experiment(parameterBlock p1, std::vector<std::vector<int64_t>> datasetVector, unsigned short int variant, unsigned int nthRepeat = 1, std::ofstream *resFile = nullptr)
{
	TimeVar t; //Obiekt ktory bedzie zliczal czas.
  	double processingTime(0.0);//Zmienna ktora bedzie przechowywac czas zliczony przez obiekt t klasy TimeVar

	bool writeToFile = (resFile != nullptr) ? true : false;
  	
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
	if (writeToFile) {
		std::cout << "\nWriting to file";
		(*resFile) << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() <<";";
		(*resFile) << p1.securityLevel <<";";
		(*resFile) << p1.dist <<";";
		(*resFile) << p1.numMults <<";";
		(*resFile) << variant <<";";
		(*resFile) << nthRepeat <<";";
	}
	std::cout << std::endl;
	
	// Initialize Public Key Containers
	LPKeyPair<DCRTPoly> keyPair;
	
	//GENEROWANIE KLUCZY ŹRÓDŁOWYCH
	
	TIC(t);//Moment rozpoczecia mierzenia czasu.
	keyPair = cryptoContext->KeyGen();//Generacja pary kluczy do szyfrowania naszych danych które będą w formacie plaintext
	processingTime = TOC(t);//Moment zakonczenia mierzenia czasu i przypisania do zmiennej. Czas dla obiektu t jest zresetowany automatycznie.
  	std::cout<<"\nSource key generation time: " <<processingTime<<"ms"<<std::endl;
	if (writeToFile) (*resFile) << processingTime <<";";
	
	//GENEROWANIE KLUCZY DLA MNOZENIA HOMOMORFICZNEGO
	TIC(t);//Moment rozpoczecia mierzenia czasu.
	cryptoContext->EvalMultKeysGen(keyPair.secretKey);//Generowanie kluczy wymaganych do operacji mnozenia homomorficznego na podstawie klucza danych źródłowych.
	processingTime = TOC(t);//Moment zakończenia mierzenia czasu.
  	std::cout<<"Key generation time for homomorphic multiplication evaluation keys: "<<processingTime<<"ms";
	if (writeToFile) (*resFile) << processingTime <<";";
	
	//WEKTOR PLAINTEXTOW
	//Tworzymy kontener na nasz dataset w formacie plaintext
	vector<Plaintext> plaintextDatasetVector;
	for(const auto &data : datasetVector)
	{
		//Konwertujemy nasz wektor liczbowy na obiekt plaintext i zapisujemy do naszego kontenera
	 	plaintextDatasetVector.push_back(cryptoContext->MakePackedPlaintext(data));
	}
	
	//WEKTOR ZASZYFROWANYCH PLAINTEXTOW (CIPHERTEXT)
	//Tworzymy kontener na nasz dataset w formie zaszyfrowanej. Tj. w formacie Ciphertext<DCRTPoly>
	vector<Ciphertext<DCRTPoly>> ciphertexts;
	
	TIC(t);//Moment rozpoczecia mierzenia czasu szyfracji.
	for(const auto &plaintext : plaintextDatasetVector)
	{
		//Zapisywanie do kontenera wartosci zaszyfrowanej naszego wektora liczbowego w formacie plaintext.
	 	ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
	}
	processingTime = TOC(t);
	std::cout << "\nTotal encryption time: "<<processingTime<<"ms";
	std::cout << "\nAverage encryption time for single plaintext: " <<processingTime / plaintextDatasetVector.size() << "ms";
	if (writeToFile) (*resFile) << processingTime <<";";
	if (writeToFile) (*resFile) << processingTime / plaintextDatasetVector.size() <<";";
	//TESTOWANIE WARIANTÓW
	switch(variant)
	{
		default:
		{	//Wariant testu musi zostać podany!	
			throw noVariantSpecifiedException();
			break;
		}
		case 1: 
		{
			//VARIANT 1
			TIC(t);
			//Dodanie WSZYSTKICH elementow zaszyfrowanych do siebie tj. <A1, A2, A3, ...> + <B1 B2, B3 ...> = <A1+B1, A2+B2, ...>
			//W naszym przypadku mamy 10 operacji ADD. Zaszyfrowany wynik jest w zmiennej ciphertextResult
			auto ciphertextResult = cryptoContext->EvalAddMany(ciphertexts);
			processingTime = TOC(t);
			std::cout << "\nTotal time of the homomorphic operations of the ciphertexts: "<<processingTime<<"ms";
			if (writeToFile) (*resFile) << processingTime << ";";
			
			//DECRYPTION
			decrypt(t, cryptoContext, keyPair, ciphertextResult, plaintextDatasetVector, resFile);
			break;			
		}
		case 2: 
		{	
			//VARIANT 2
			TIC(t);
			//Mnozenie WSZYSTKICH elementow zaszyfrowanych do siebie tj.  <A1, A2, A3, ...> * <B1 B2, B3 ...> = <A1B1, A2B2, ...>
			auto ciphertextResult = cryptoContext->EvalMultMany(ciphertexts);
			processingTime = TOC(t);
			std::cout << "\nTotal time of the homomorphic operations of the ciphertexts:: "<<processingTime<<"ms"<<std::endl;
			if (writeToFile) (*resFile) << processingTime << ";";
				
			//DECRYPTION
			decrypt(t, cryptoContext, keyPair, ciphertextResult, plaintextDatasetVector, resFile);
			break;
		}
		case 3: 
		{	
			//VARIANT 3
			//Tworzymy subsety naszych wartosci manipulajac przedzialami z powodu natury testu (polowa ADD, polowa MUL)
			vector<Ciphertext<DCRTPoly>> ciphertextsSubset1 = {ciphertexts.begin(), ciphertexts.begin()+4};
			vector<Ciphertext<DCRTPoly>> ciphertextsSubset2 = {ciphertexts.begin()+5, ciphertexts.begin()+9};
			
			TIC(t);
			//Dodajemy wszystkie elementy subsetu pierwszego do siebie analogicznie jak w wariancie 1.
			//Mnozymy wszystkie elementy subsetu drugiego do siebie analogicznie jak w wariancie 2
			//UWAGA: Nalezy pamietac, dobrze policzyc liczbe operacji bo 1 powinna zostac na polaczenie obu subsetow.
			//UWAGA: Mamy EvalMult i EvalMultMany. Jedna przyjmuje 2 argumenty w postaci pojedynczych elementow, druga 1 argument w postaci zbioru.
			auto ciphertextResultS1 = cryptoContext->EvalAddMany(ciphertextsSubset1);
			auto ciphertextResultS2 = cryptoContext->EvalMultMany(ciphertextsSubset2);
			auto ciphertextResult = cryptoContext->EvalMult(ciphertextResultS1, ciphertextResultS2);
			processingTime = TOC(t);
			std::cout << "\nTotal time of the homomorphic operations of the ciphertexts:: "<<processingTime<<"ms"<<std::endl;
			if (writeToFile) (*resFile) << processingTime << ";";
				
			//DECRYPTION
			decrypt(t, cryptoContext, keyPair, ciphertextResult, plaintextDatasetVector, resFile);
			break;
		}
		case 4: 
		{	
			//VARIANT 4
			vector<Ciphertext<DCRTPoly>> ciphertextsSubset1 = {ciphertexts.begin(), ciphertexts.begin()+4};
			vector<Ciphertext<DCRTPoly>> ciphertextsSubset2 = {ciphertexts.begin()+5, ciphertexts.begin()+9};
			
			TIC(t);
			auto ciphertextResultS1 = cryptoContext->EvalMultMany(ciphertextsSubset1);
			auto ciphertextResultS2 = cryptoContext->EvalAddMany(ciphertextsSubset2);
			auto ciphertextResult = cryptoContext->EvalAdd(ciphertextResultS1, ciphertextResultS2);
			processingTime = TOC(t);
			std::cout << "\nTotal time of the homomorphic operations of the ciphertexts:: "<<processingTime<<"ms"<<std::endl;
			if (writeToFile) (*resFile) << processingTime << ";";
				
			//DECRYPTION
			decrypt(t, cryptoContext, keyPair, ciphertextResult, plaintextDatasetVector, resFile);
			break;	
		}
		case 5: 
		{	
			//VARIANT 5
			vector<Ciphertext<DCRTPoly>> ciphertextsSubset1 = {ciphertexts.begin(), ciphertexts.begin()+2};
			vector<Ciphertext<DCRTPoly>> ciphertextsSubset2 = {ciphertexts.begin()+3, ciphertexts.begin()+9};
			
			TIC(t);
			auto ciphertextResultS1 = cryptoContext->EvalAddMany(ciphertextsSubset1);
			auto ciphertextResultS2 = cryptoContext->EvalMultMany(ciphertextsSubset2);
			auto ciphertextResult = cryptoContext->EvalAdd(ciphertextResultS1, ciphertextResultS2);
			processingTime = TOC(t);
			std::cout << "\nTotal time of the homomorphic operations of the ciphertexts:: "<<processingTime<<"ms"<<std::endl;
			if (writeToFile) (*resFile) << processingTime << ";";
				
			//DECRYPTION
			decrypt(t, cryptoContext, keyPair, ciphertextResult, plaintextDatasetVector, resFile);
			break;	
		}
		case 6: 
		{	
			//VARIANT 6
			vector<Ciphertext<DCRTPoly>> ciphertextsSubset1 = {ciphertexts.begin(), ciphertexts.begin()+1};
			vector<Ciphertext<DCRTPoly>> ciphertextsSubset2 = {ciphertexts.begin()+2, ciphertexts.begin()+9};
			
			TIC(t);
			auto ciphertextResultS1 = cryptoContext->EvalMultMany(ciphertextsSubset1);
			auto ciphertextResultS2 = cryptoContext->EvalAddMany(ciphertextsSubset2);
			auto ciphertextResult = cryptoContext->EvalAdd(ciphertextResultS1, ciphertextResultS2);
			processingTime = TOC(t);
			std::cout << "\nTotal time of the homomorphic operations of the ciphertexts:: "<<processingTime<<"ms"<<std::endl;
			if (writeToFile) (*resFile) << processingTime << ";";
				
			//DECRYPTION
			decrypt(t, cryptoContext, keyPair, ciphertextResult, plaintextDatasetVector, resFile);
			break;	
		}
		case 7: 
		{	
			//VARIANT 7
			vector<Ciphertext<DCRTPoly>> ciphertextsSubset1 = {ciphertexts.begin(), ciphertexts.begin()+1};
			vector<Ciphertext<DCRTPoly>> ciphertextsSubset2 = {ciphertexts.begin()+2, ciphertexts.begin()+9};
			
			TIC(t);
			auto ciphertextResultS1 = cryptoContext->EvalAddMany(ciphertextsSubset1);
			auto ciphertextResultS2 = cryptoContext->EvalMultMany(ciphertextsSubset2);
			auto ciphertextResult = cryptoContext->EvalMult(ciphertextResultS1, ciphertextResultS2);
			processingTime = TOC(t);
			std::cout << "\nTotal time of the homomorphic operations of the ciphertexts:: "<<processingTime<<"ms"<<std::endl;
			if (writeToFile) (*resFile) << processingTime << ";";
				
			//DECRYPTION
			decrypt(t, cryptoContext, keyPair, ciphertextResult, plaintextDatasetVector, resFile);
			break;	
		}
		case 8: 
		{	
			//VARIANT 8
			TIC(t);
			//TODO: for loop
			auto ciphertextResultS1 = cryptoContext->EvalAdd(ciphertexts[0], ciphertexts[1]);
			auto ciphertextResultS2 = cryptoContext->EvalMult(ciphertextResultS1, ciphertexts[2]);
			auto ciphertextResultS3 = cryptoContext->EvalAdd(ciphertextResultS2, ciphertexts[3]);
			auto ciphertextResultS4 = cryptoContext->EvalMult(ciphertextResultS3, ciphertexts[4]);
			auto ciphertextResultS5 = cryptoContext->EvalAdd(ciphertextResultS4, ciphertexts[5]);
			auto ciphertextResultS6 = cryptoContext->EvalMult(ciphertextResultS5, ciphertexts[6]);
			auto ciphertextResultS7 = cryptoContext->EvalAdd(ciphertextResultS6, ciphertexts[7]);
			auto ciphertextResultS8 = cryptoContext->EvalMult(ciphertextResultS7, ciphertexts[8]);
			auto ciphertextResultS9 = cryptoContext->EvalAdd(ciphertextResultS8, ciphertexts[9]);
			auto ciphertextResult = cryptoContext->EvalMult(ciphertextResultS9, ciphertextResultS9);
			
			processingTime = TOC(t);
			std::cout << "\nTotal time of the homomorphic operations of the ciphertexts:: "<<processingTime<<"ms"<<std::endl;
			if (writeToFile) (*resFile) << processingTime << ";";
				
			//DECRYPTION
			decrypt(t, cryptoContext, keyPair, ciphertextResult, plaintextDatasetVector, resFile);
			break;
		}
		case 9: 
		{	
			vector<Ciphertext<DCRTPoly>> ciphertextsSubset1 = {ciphertexts.begin(), ciphertexts.begin()+3};
			vector<Ciphertext<DCRTPoly>> ciphertextsSubset2 = {ciphertexts.begin()+4, ciphertexts.begin()+6};
			vector<Ciphertext<DCRTPoly>> ciphertextsSubset3 = {ciphertexts.begin()+7, ciphertexts.begin()+9};
			//VARIANT 9
			TIC(t);
			auto ciphertextResultS1 = cryptoContext->EvalAddMany(ciphertextsSubset1);
			auto ciphertextResultS2 = cryptoContext->EvalMultMany(ciphertextsSubset2);
			auto ciphertextResultS3 = cryptoContext->EvalAddMany(ciphertextsSubset3);
			auto ciphertextResultS4 = cryptoContext->EvalAdd(ciphertextResultS1, ciphertextResultS2);
			auto ciphertextResult = cryptoContext->EvalAdd(ciphertextResultS3, ciphertextResultS4);
			
			processingTime = TOC(t);
			std::cout << "\nTotal time of the homomorphic operations of the ciphertexts:: "<<processingTime<<"ms"<<std::endl;
			if (writeToFile) (*resFile) << processingTime << ";";
				
			//DECRYPTION
			decrypt(t, cryptoContext, keyPair, ciphertextResult, plaintextDatasetVector, resFile);
			break;	
		}
		case 10: 
		{	
			vector<Ciphertext<DCRTPoly>> ciphertextsSubset1 = {ciphertexts.begin(), ciphertexts.begin()+2};
			vector<Ciphertext<DCRTPoly>> ciphertextsSubset2 = {ciphertexts.begin()+3, ciphertexts.begin()+7};
			
			//VARIANT 9
			TIC(t);
			auto ciphertextResultS1 = cryptoContext->EvalMultMany(ciphertextsSubset1);
			auto ciphertextResultS2 = cryptoContext->EvalAddMany(ciphertextsSubset2);
			auto ciphertextResultS3 = cryptoContext->EvalAdd(ciphertextResultS1,ciphertextResultS2);
			auto ciphertextResultS4 = cryptoContext->EvalMult(ciphertextResultS3, ciphertexts[8]);
			auto ciphertextResult = cryptoContext->EvalAdd(ciphertextResultS4, ciphertexts[9]);
			
			processingTime = TOC(t);
			std::cout << "\nTotal time of the homomorphic operations of the ciphertexts:: "<<processingTime<<"ms"<<std::endl;
			if (writeToFile) (*resFile) << processingTime << ";";
			
			//DECRYPTION
			decrypt(t, cryptoContext, keyPair, ciphertextResult, plaintextDatasetVector, resFile);
			break;	
		}
	}
	std::cout<<"Raw input data size: "<<sizeof(int64_t) * datasetVector.size() <<" Bytes"<<std::endl;
	std::cout<<"Plaintext data size: "<<sizeof(Plaintext) * plaintextDatasetVector.size() <<" Bytes"<<std::endl;
	std::cout<<"Encrypted data size: "<<sizeof(Ciphertext<DCRTPoly>) * ciphertexts.size() <<" v"<<std::endl;
}

//Funkcja która bierze pierwszą spełniającą warunki PALISADE liczbę pierwszą równą bądź większą od naszej proponowanej
uint64_t modulusPicker(long long unsigned int approxDesiredModulus = 536903681, long unsigned int cyclotomicOrder = 65536, bool debug=0)
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
    //auto c = Clock();
    
	//Wywołanie funkcji modulusPicker:
	// 1 - przybliżony docelowy modulus
	// 2 - rząd cyklotomiczny (m) - default: 65536. 
	// UWAGA: W przypadku dobrania zbyt rozbieżnego zestawu parametrów może zaistnieć potrzeba zmiany cyclotomicOrder na wartość zaproponowaną z konsoli
	// 3 - flaga do debugowania, wyświetlania. Domyślnie wyłączona tj. debug = 0
	
	//Wynik funkcji zostanie wybrany na nasz modulus. Patrz opis/definicje funkcji
	
	//uint64_t mydebugModulus = modulusPicker(1000,3,1)
	// uint64_t myModulus = modulusPicker(536903681);
	// uint64_t myModulus2 = modulusPicker(375049);
	// uint64_t myModulus3 = modulusPicker(10002191);
	// uint64_t myModulus4 = modulusPicker(75005101);
	// uint64_t myModulus5 = modulusPicker(9750005347);
	
    //Przyklad instancji zestawu parametrow. 
	//Odpowiednio: 
	//Modulus(plaintextModulus) - liczba pierwsza spelniajaca okreslony warunek (zalatwiane funkcja modulusPicker), 
	//Poziom zabezpieczen(securityLevel), długość klucza - HEStd_128_classic lub HEStd_192_classic, HEStd_256_classic
	//Wskaźnik odchylenia standardowego dla szumu gaussa (dist)
	//Maksymalna głębokość mnożeń (numMults)
	
	// parameterBlock p1(myModulus, HEStd_128_classic, 3.2, 3);
	// parameterBlock p2(myModulus2, HEStd_128_classic, 3.2, 3);
	// parameterBlock p3(myModulus3, HEStd_128_classic, 3.2, 3);
	// parameterBlock p4(myModulus4, HEStd_128_classic, 3.2, 3);
	// parameterBlock p5(myModulus5, HEStd_128_classic, 3.2, 3);
	
	// parameterBlock p6(myModulus, HEStd_128_classic, 3.2, 3);
	// parameterBlock p7(myModulus2, HEStd_192_classic, 3.2, 3);
	// parameterBlock p8(myModulus, HEStd_192_classic, 3.2, 3);
	// parameterBlock p9(myModulus2, HEStd_256_classic, 3.2, 3);
	// parameterBlock p10(myModulus, HEStd_256_classic, 3.2, 3);
	
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
	
	// unsigned short int variant=1;//Wybrany wariant testu

	//Testowane warianty parametrów
	vector<long long unsigned int> testedModulusesInt = {
		536903681, 400051, 321312269, 7672487, 821312234893, 921312236417
	};
	vector<SecurityLevel> testedSecurityLevels = {
		HEStd_128_classic, HEStd_192_classic, HEStd_256_classic
	};
	vector<float> testedDists = {
		3.2
		// , 5.4, 8.2, 30.6, 1.7, 0.8, 0.2, 0.01, 0.001
	};
	vector<unsigned int> testedNumMults = {
		// 1, 2, 
		3
		// , 4, 6, 8, 10, 15, 20
	};
	vector<unsigned short int> testedVariants = {1, 2, 3, 8, 9};
	unsigned int repeat = 5;//Powtórz eksperyment n razy z tymi samymi parametrami

	std::string  resFileName = "../results9";//Plik z wynikami
	vector<std::ofstream> resFiles;

	if (repeat == 1)
	{
		resFiles.emplace_back(std::ofstream{ resFileName + ".csv" });
		resFiles[0] << "ptMod;securityLevel;dist;numMults;variant;nthRep;"
			<< "keyGenTime;keyGen4HMEkeys;totEncTime;avgEncTime;totHomOpr;decTime" <<std::endl;
	}
	else
	{
		for (unsigned int i = 0; i < repeat; i++)
		{
			int len = ceil(log10(repeat));
			std::string str_i = std::to_string(i);
			resFiles.emplace_back(std::ofstream{
					resFileName + "-part" +
					std::string(len - str_i.length(), '0') + str_i +
					".csv"
				});
			resFiles[i] << "ptMod;securityLevel;dist;numMults;variant;nthRep;"
				<< "keyGenTime;keyGen4HMEkeys;totEncTime;avgEncTime;totHomOpr;decTime" <<std::endl;//Nagłówek w pliku z wynikami
		}
		
	}


	int numToTest = testedModulusesInt.size() * testedSecurityLevels.size() * testedDists.size() *
					 testedNumMults.size() * testedVariants.size() * repeat;
	int numTested = 0;
	for (unsigned int rep=0; rep<repeat; rep++)
		for (auto &currModulus : testedModulusesInt)
			for (auto &currSecLvl : testedSecurityLevels)
				for (auto &currDist : testedDists)
					for (auto &currNumMults : testedNumMults)
						for (auto &currTestedVariant : testedVariants)
						{
							parameterBlock params(modulusPicker(currModulus), currSecLvl, currDist, currNumMults);
							experiment(params,datasetVector,currTestedVariant,rep,&resFiles[rep]);
							std::cout << "Progress (total " << numToTest << ") tested: " << ++numTested << std::endl;
						}

	
	// experiment(p1,datasetVector,variant);
	// experiment(p2,datasetVector,2);
	// experiment(p3,datasetVector,3);
	// experiment(p4,datasetVector,4);
	// experiment(p5,datasetVector,5);
	
	// experiment(p1,datasetVector,6);
	// experiment(p2,datasetVector,7);
	// experiment(p3,datasetVector,8);
	// experiment(p4,datasetVector,9);
	// experiment(p5,datasetVector,10);
	//TODO: ... more experiments
}


