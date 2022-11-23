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

//USED SCHEMA: BFVrns  - Brakerski-Fan-Vercauteren Residue Number System – breaks rings of large bit-width integers into a parallel set of rings using < 64 bit residues, allowing very efficient computation on 64-bit CPU architectures
//Key switching after multiplication is called relinearization

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
	vector<string> variantCheatSheet =
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
	
	//WEKTOR PLAINTEXTOW
	//Tworzymy kontener na nasz dataset w formacie plaintext
	vector<Plaintext> plaintextDatasetVector;
	for(unsigned int i = 0; i<datasetVector.size(); i++)
	{
		//Konwertujemy nasz wektor liczbowy na obiekt plaintext i zapisujemy do naszego kontenera
	 	Plaintext p = cryptoContext->MakePackedPlaintext(datasetVector[i]);
	 	plaintextDatasetVector.push_back(p);
	}
	
	//WEKTOR ZASZYFROWANYCH PLAINTEXTOW (CIPHERTEXT)
	//Tworzymy kontener na nasz dataset w formie zaszyfrowanej. Tj. w formacie Ciphertext<DCRTPoly>
	vector<Ciphertext<DCRTPoly>> ciphertexts;
	
	TIC(t);//Moment rozpoczecia mierzenia czasu szyfracji.
	for(unsigned int i = 0; i<plaintextDatasetVector.size(); i++)
	{
		//Zapisywanie do kontenera wartosci zaszyfrowanej naszego wektora liczbowego w formacie plaintext.
	 	ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintextDatasetVector[i]));
	}
	processingTime = TOC(t);
	std::cout << "\nTotal encryption time: "<<processingTime<<"ms";
	std::cout << "\nAverage encryption time for single plaintext: " <<processingTime / plaintextDatasetVector.size() << "ms";
	
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
			
			//DECRYPTION
			Plaintext plaintextResult;//Zmienna wynikowa plaintext do odczytu
			TIC(t);//Moment rozpoczecia mierzenia czasu deszyfracji
			//Deszyfracja ciphertextResult na podstawie klucza w odniesieniu do cryptocontextu i zapisanie do plaintextResult
			cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextResult);
			processingTime = TOC(t);
			std::cout << "\nDecryption time: " << processingTime << "ms" << std::endl;
			plaintextResult->SetLength(plaintextDatasetVector[0]->GetLength());//Ustawienie dlugosci wyswietlania wyniku na podstawie batchSize.
			std::cout <<"\nDecryption result: "<< plaintextResult << std::endl;
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
				
			//DECRYPTION
			Plaintext plaintextResult;
			TIC(t);
			cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextResult);
			processingTime = TOC(t);
			std::cout << "\nDecryption time: " << processingTime << "ms" << std::endl;
			plaintextResult->SetLength(plaintextDatasetVector[0]->GetLength());
			std::cout <<"\nDecryption result: "<< plaintextResult << std::endl;
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
				
			//DECRYPTION
			Plaintext plaintextResult;
			TIC(t);
			cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextResult);
			processingTime = TOC(t);
			std::cout << "\nDecryption time: " << processingTime << "ms" << std::endl;
			plaintextResult->SetLength(plaintextDatasetVector[0]->GetLength());
			std::cout <<"\nDecryption result: "<< plaintextResult << std::endl;
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
				
			//DECRYPTION
			Plaintext plaintextResult;
			TIC(t);
			cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextResult);
			processingTime = TOC(t);
			std::cout << "\nDecryption time: " << processingTime << "ms" << std::endl;
			plaintextResult->SetLength(plaintextDatasetVector[0]->GetLength());
			std::cout <<"\nDecryption result: "<< plaintextResult << std::endl;
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
				
			//DECRYPTION
			Plaintext plaintextResult;
			TIC(t);
			cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextResult);
			processingTime = TOC(t);
			std::cout << "\nDecryption time: " << processingTime << "ms" << std::endl;
			plaintextResult->SetLength(plaintextDatasetVector[0]->GetLength());
			std::cout <<"\nDecryption result: "<< plaintextResult << std::endl;
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
				
			//DECRYPTION
			Plaintext plaintextResult;
			TIC(t);
			cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextResult);
			processingTime = TOC(t);
			std::cout << "\nDecryption time: " << processingTime << "ms" << std::endl;
			plaintextResult->SetLength(plaintextDatasetVector[0]->GetLength());
			std::cout <<"\nDecryption result: "<< plaintextResult << std::endl;
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
				
			//DECRYPTION
			Plaintext plaintextResult;
			TIC(t);
			cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextResult);
			processingTime = TOC(t);
			std::cout << "\nDecryption time: " << processingTime << "ms" << std::endl;
			plaintextResult->SetLength(plaintextDatasetVector[0]->GetLength());
			std::cout <<"\nDecryption result: "<< plaintextResult << std::endl;
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
				
			//DECRYPTION
			Plaintext plaintextResult;
			TIC(t);
			cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextResult);
			processingTime = TOC(t);
			std::cout << "\nDecryption time: " << processingTime << "ms" << std::endl;
			plaintextResult->SetLength(plaintextDatasetVector[0]->GetLength());
			std::cout <<"\nDecryption result: "<< plaintextResult << std::endl;
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
				
			//DECRYPTION
			Plaintext plaintextResult;
			TIC(t);
			cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextResult);
			processingTime = TOC(t);
			std::cout << "\nDecryption time: " << processingTime << "ms" << std::endl;
			plaintextResult->SetLength(plaintextDatasetVector[0]->GetLength());
			std::cout <<"\nDecryption result: "<< plaintextResult << std::endl;
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
			
			//DECRYPTION
			Plaintext plaintextResult;
			TIC(t);
			cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextResult);
			processingTime = TOC(t);
			std::cout << "\nDecryption time: " << processingTime << "ms" << std::endl;
			plaintextResult->SetLength(plaintextDatasetVector[0]->GetLength());
			std::cout <<"\nDecryption result: "<< plaintextResult << std::endl;
			break;	
		}
		
	}
}

   
int main() 
{
    //auto c = Clock();
    
    //WIP: Szukanie odpowiedniego modulusa na podstawie liczby bitow
	//auto plaintextModulus = FirstPrime<NativeInteger>(bits, 2*n);
	
    //Przyklad instancji zestawu parametrow. 
	//Odpowiednio: 
	//Modulus(plaintextModulus) - liczba pierwsza spelniajaca okreslony warunek (zalatwimy to funkcja wyzej), 
	//Poziom zabezpieczen(securityLevel) - HEStd_128_classic lub HEStd_192_classic, HEStd_256_classic
	//Wskaźnik odchylenia standardowego dla szumu gaussa (dist)
	//Maksymalna głębokość mnożeń (numMults)
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


