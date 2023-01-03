#include <vector>
#include <iostream>
#include <sstream>
#include <cstdlib>

#include <crypto++/cryptlib.h>
#include <crypto++/hrtimer.h>
#include <crypto++/modes.h>
#include <crypto++/config.h>
#include <crypto++/aes.h>
#include <crypto++/filters.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>

std::string encrypt(const std::string& input, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
    std::string cipher;
    
    auto aes = CryptoPP::AES::Encryption(key.data(), key.size());
    auto aes_cbc = CryptoPP::CBC_Mode_ExternalCipher::Encryption(aes, iv.data());
    
    CryptoPP::StringSource ss(
        input, 
        true, 
        new CryptoPP::StreamTransformationFilter(
            aes_cbc, 
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(cipher)
            )
        )
    );
    return cipher;
}

std::string decrypt(const std::string& cipher_text, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) 
{
    std::string plain_text;
    
    auto aes = CryptoPP::AES::Decryption(key.data(), key.size());
    auto aes_cbc = CryptoPP::CBC_Mode_ExternalCipher::Decryption(aes, iv.data());
    
    CryptoPP::StringSource ss(
        cipher_text, 
        true, 
        new CryptoPP::Base64Decoder(
            new CryptoPP::StreamTransformationFilter(
                aes_cbc, 
                new CryptoPP::StringSink(plain_text)
            )
        )
    );

    return plain_text;
}
 
void experimentAES(std::string input, std::size_t AES_KEY_SIZE, CryptoPP::Timer timer)
{
    double elapsedTime=0.0;
	
	//Generowanie kluczy
	timer.StartTimer();
	
    std::vector<uint8_t> key(AES_KEY_SIZE);
    std::vector<uint8_t> iv(CryptoPP::AES::BLOCKSIZE);

    elapsedTime = timer.ElapsedTimeAsDouble();
    std::cout<<"\nKey generation time for "<<AES_KEY_SIZE*8<<" bit key (us): "<<elapsedTime<<std::endl;
    
	timer.StartTimer();
	
    CryptoPP::BlockingRng rand;
    rand.GenerateBlock(key.data(), key.size());
    rand.GenerateBlock(iv.data(), iv.size());
    
	elapsedTime = timer.ElapsedTimeAsDouble();
	std::cout<<"\nInitialization vector and block generation time (us): "<<elapsedTime<<std::endl;
	
	
	timer.StartTimer();
	
    auto cipher = encrypt(input, key, iv);
    
    elapsedTime = timer.ElapsedTimeAsDouble();
	std::cout<<"\nEncryption time (us): "<<elapsedTime<<std::endl;
    
    
	timer.StartTimer();
	
    auto plain_text = decrypt(cipher, key, iv);
    
	elapsedTime = timer.ElapsedTimeAsDouble();
	std::cout<<"\nDecryption time (us): "<<elapsedTime<<std::endl;

    if(plain_text != input) 
	{
        std::cout << "\nData after Encryption & Decryption is diffrent!!!" << std::endl;
    }
	//std::cout<<"\nRESULT (After Decryption): "<<plain_text<<std::endl;
	
}
int main()
{	

	//CryptoPP::ThreadUserTimer timerBase(CryptoPP::TimerBase::Unit unit = CryptoPP::TimerBase::MILLISECONDS, bool stuckAtZero = false);
    
    constexpr size_t AES_KEY_SIZE_128 = 16; //AES-128
    constexpr size_t AES_KEY_SIZE_192 = 24; //AES-192
    constexpr size_t AES_KEY_SIZE_256 = 32; //AES-256
    
    //Zegar, precyzja 
    CryptoPP::Timer timer(CryptoPP::Timer::MICROSECONDS);
    
   	std::vector<unsigned short int> dataSetVector;//10x10
   	const short int vectorSize = 10;
   	const short int numberOfVectors = 10;
   	const int fullSize = vectorSize*numberOfVectors;
   	
   	std::stringstream inputStream;
   	srand((unsigned) time(NULL));
   	
   	for(int i = 0; i<fullSize;i++)
   	{
   		unsigned short int sampleValue = (rand()%10)+1;
   		dataSetVector.push_back(sampleValue);
   		inputStream<<dataSetVector[i];
	}
	//Dataset Loading
    const std::string input = inputStream.str();
    //std::cout<<"\nINPUT-DATA-STRING: (Before Encryption): "<<input<<std::endl;
    
    experimentAES(input,AES_KEY_SIZE_128,timer);
    experimentAES(input,AES_KEY_SIZE_192,timer);
	experimentAES(input,AES_KEY_SIZE_256,timer);
 
	return 0;
}
