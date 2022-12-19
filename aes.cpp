#include <vector>
#include <iostream>

#include <crypto++/cryptlib.h>
#include <crypto++/hrtimer.h>
#include <crypto++/modes.h>
#include <crypto++/config.h>
#include <crypto++/aes.h>
#include <crypto++/filters.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>

std::string int_vector_to_string(const std::vector<unsigned short> &v1)
{
    std::string res = "";
    for(const auto &x : v1)
    {
        res += (char)x;
    }
    return res;
}

std::vector<unsigned short> string_to_int_vector(const std::string &s)
{
    std::vector<unsigned short> res;
    for(const auto &x : s)
    {
        res.push_back((unsigned short)x);
    }
    return res;
}

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

int main()
{

	//CryptoPP::ThreadUserTimer timerBase(CryptoPP::TimerBase::Unit unit = CryptoPP::TimerBase::MILLISECONDS, bool stuckAtZero = false);
    double elapsedTime;
    
    static constexpr size_t AES_KEY_SIZE_128 = 128 / 8; //AES-128
    static constexpr size_t AES_KEY_SIZE_192 = 192 / 8; //AES-192
    static constexpr size_t AES_KEY_SIZE_256 = 256 / 8; //AES-256
   
    const std::string input {"123456789"};
    std::cout<<"\nINPUT-DATA: (Before Encryption): "<<input<<std::endl;
    elapsedTime = 0;
	CryptoPP::Timer timer(CryptoPP::Timer::MILLISECONDS);
	timer.StartTimer();
	
    std::vector<uint8_t> key(AES_KEY_SIZE_128);
    std::vector<uint8_t> iv(CryptoPP::AES::BLOCKSIZE);
    
	elapsedTime = timer.ElapsedTimeAsDouble();
	
	std::cout<<"\nKey generation (ms): "<<elapsedTime<<std::endl;
	
	elapsedTime = 0;
	timer.StartTimer();
	
    CryptoPP::BlockingRng rand;
    rand.GenerateBlock(key.data(), key.size());
    rand.GenerateBlock(iv.data(), iv.size());
    
	elapsedTime = timer.ElapsedTimeAsDouble();
	
	std::cout<<"\nInitialization vector and block generation time (ms): "<<elapsedTime<<std::endl;
	
	elapsedTime = 0;
	timer.StartTimer();
	
    auto cipher = encrypt(input, key, iv);
    
    elapsedTime = timer.ElapsedTimeAsDouble();
	
	std::cout<<"\nEncryption time (ms): "<<elapsedTime<<std::endl;
    
    elapsedTime = 0;
	timer.StartTimer();
	
    auto plain_text = decrypt(cipher, key, iv);
    
    elapsedTime = timer.ElapsedTimeAsDouble();
	
	std::cout<<"\nDecryption time (ms): "<<elapsedTime<<std::endl;

    if(plain_text != input) {
        std::cout << "\nData after Encryption & Decryption is diffrent!!!" << std::endl;
    }
	std::cout<<"\nRESULT (After Decryption): "<<plain_text<<std::endl;
    return 0;
}
