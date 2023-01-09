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
#include <crypto++/seckey.h>
#include <crypto++/secblock.h>
#include <crypto++/hex.h>
#include <crypto++/osrng.h>
#include <crypto++/files.h>

int main(int argc, char* argv[])
{
    using namespace CryptoPP;
    
    CryptoPP::Timer timer(CryptoPP::Timer::MICROSECONDS);
    
	bool display = false;
	double elapsedTime = 0.0;
	
	constexpr size_t AES_KEY_SIZE_128 = 16; //AES-128
    constexpr size_t AES_KEY_SIZE_192 = 24; //AES-192
    constexpr size_t AES_KEY_SIZE_256 = 32; //AES-256
    
    AutoSeededRandomPool prng;
    HexEncoder encoder(new FileSink(std::cout));

    SecByteBlock key(AES_KEY_SIZE_128);
    SecByteBlock iv(AES::BLOCKSIZE);
	
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());
    
	////
	////Dataset creation and loading
	////
	
	
	std::vector<unsigned short int> dataSetVector;//10x10 default palisade
   	const short int vectorSize = 10;
   	const int numberOfVectors = 10000000;
   	const int fullSize = vectorSize*numberOfVectors;
   	
   	std::stringstream inputStream;
   	srand((unsigned) time(NULL));
   	timer.StartTimer();
   	
   	for(int i = 0; i<fullSize;i++)
   	{
   		unsigned short int sampleValue = (rand()%10)+1;
   		dataSetVector.push_back(sampleValue);
   		inputStream<<dataSetVector[i];
	}
	elapsedTime = timer.ElapsedTimeAsDouble();
	std::cout<<"\nDataset creation time (us): "<<elapsedTime<<std::endl;
	elapsedTime = 0.0;
	
	//Dataset Loading
    const std::string input = inputStream.str();
    
    //Creating plaintext input, cipher string and decrypted string for AES
    std::string plain = input;
    std::string cipher, decrypted;

    
    std::cout << "Plain Text (" << plain.size() << " bytes)" << std::endl;
    if(display)
    {
    	std::cout << plain;
	}
	
	////
	////ENCRYPTION
	////
    try
    {	
    	timer.StartTimer();
    	
        CBC_Mode< AES >::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);
		
        StringSource s(plain, true, 
            new StreamTransformationFilter(e,
                new StringSink(cipher)
            ) // StreamTransformationFilter
        ); // StringSource
        elapsedTime = timer.ElapsedTimeAsDouble();
		std::cout<<"\nEncryption time (us): "<<elapsedTime<<std::endl;
		elapsedTime = 0.0;
    }
    catch(const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
    
	////
	////DISPLAY
	////
    std::cout << "Key: ";
    encoder.Put(key, key.size());
    encoder.MessageEnd();
    std::cout << " Key length: "<<key.size()<<" bytes"<<std::endl;

    std::cout << "iv: ";
    encoder.Put(iv, iv.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::cout << "Cipher Text (" << cipher.size() << " bytes)" << std::endl;
    
    if(display)
    {	
    	encoder.Put((const byte*)&cipher[0], cipher.size());
    	encoder.MessageEnd();
    	std::cout << std::endl;
	}
	////
	////DECRYPTION
	////
    try
    {	timer.StartTimer();
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);
		
        StringSource s(cipher, true, 
            new StreamTransformationFilter(d,
                new StringSink(decrypted)
            ) // StreamTransformationFilter
        ); // StringSource
        
        elapsedTime = timer.ElapsedTimeAsDouble();
		std::cout<<"\nDecryption time (us): "<<elapsedTime<<std::endl;
		elapsedTime = 0.0;
		
        std::cout << "Decrypted Text (" << decrypted.size() << " bytes)" << std::endl;
		if(display)
		{
			std::cout << "Decrypted text: " << decrypted << std::endl;
		}
        
    }
    catch(const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    return 0;
}
