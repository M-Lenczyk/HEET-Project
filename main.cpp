#include "palisade.h"
#include "utils.cpp"
#include <thread>

using namespace lbcrypto;



int main() 
{
    auto c = Clock();
    std::vector<int> v1 = {1,2,3,4};
    std::vector<int> v2 = {7,6,5,4};

    std::cout<<vector_statistic_combined(v1,v2).to_string()<<std::endl;
    std::cout<<"elapsed time (ms): "<<c.getElapsedTime().asMilliseconds();
    return 0;
}



void palisade_test()
{
  // Sample Program: Step 1: Set CryptoContext

  // Set the main parameters
  int plaintextModulus = 65537;
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic;
  uint32_t depth = 2;

  // Instantiate the crypto context
  CryptoContext<DCRTPoly> cryptoContext =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          plaintextModulus, securityLevel, sigma, 0, depth, 0, OPTIMIZED);

  // Enable features that you wish to use
  cryptoContext->Enable(ENCRYPTION);
  cryptoContext->Enable(SHE);

  // Sample Program: Step 2: Key Generation

  // Initialize Public Key Containers
  LPKeyPair<DCRTPoly> keyPair;

  // Generate a public/private key pair
  keyPair = cryptoContext->KeyGen();

  // Generate the relinearization key
  cryptoContext->EvalMultKeyGen(keyPair.secretKey);

  // Generate the rotation evaluation keys
  cryptoContext->EvalAtIndexKeyGen(keyPair.secretKey, {1, 2, -1, -2});

  // Sample Program: Step 3: Encryption

  // First plaintext vector is encoded
  std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);
  // Second plaintext vector is encoded
  std::vector<int64_t> vectorOfInts2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);
  // Third plaintext vector is encoded
  std::vector<int64_t> vectorOfInts3 = {1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12};
  Plaintext plaintext3 = cryptoContext->MakePackedPlaintext(vectorOfInts3);

  // The encoded vectors are encrypted
  auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
  auto ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);

  // Sample Program: Step 4: Evaluation

  // Homomorphic additions
  auto ciphertextAdd12 = cryptoContext->EvalAdd(ciphertext1, ciphertext2);
  auto ciphertextAddResult =
      cryptoContext->EvalAdd(ciphertextAdd12, ciphertext3);

  // Homomorphic multiplications
  auto ciphertextMul12 = cryptoContext->EvalMult(ciphertext1, ciphertext2);
  auto ciphertextMultResult =
      cryptoContext->EvalMult(ciphertextMul12, ciphertext3);

  // Homomorphic rotations
  auto ciphertextRot1 = cryptoContext->EvalAtIndex(ciphertext1, 1);
  auto ciphertextRot2 = cryptoContext->EvalAtIndex(ciphertext1, 2);
  auto ciphertextRot3 = cryptoContext->EvalAtIndex(ciphertext1, -1);
  auto ciphertextRot4 = cryptoContext->EvalAtIndex(ciphertext1, -2);

  // Sample Program: Step 5: Decryption

  // Decrypt the result of additions
  Plaintext plaintextAddResult;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddResult,
                         &plaintextAddResult);

  // Decrypt the result of multiplications
  Plaintext plaintextMultResult;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextMultResult,
                         &plaintextMultResult);

  // Decrypt the result of rotations
  Plaintext plaintextRot1;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot1, &plaintextRot1);
  Plaintext plaintextRot2;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot2, &plaintextRot2);
  Plaintext plaintextRot3;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot3, &plaintextRot3);
  Plaintext plaintextRot4;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot4, &plaintextRot4);

  plaintextRot1->SetLength(vectorOfInts1.size());
  plaintextRot2->SetLength(vectorOfInts1.size());
  plaintextRot3->SetLength(vectorOfInts1.size());
  plaintextRot4->SetLength(vectorOfInts1.size());

  std::cout << "Plaintext #1: " << plaintext1 << std::endl;
  std::cout << "Plaintext #2: " << plaintext2 << std::endl;
  std::cout << "Plaintext #3: " << plaintext3 << std::endl;

  // Output results
  std::cout << "\nResults of homomorphic computations" << std::endl;
  std::cout << "#1 + #2 + #3: " << plaintextAddResult << std::endl;
  std::cout << "#1 * #2 * #3: " << plaintextMultResult << std::endl;
  std::cout << "Left rotation of #1 by 1: " << plaintextRot1 << std::endl;
  std::cout << "Left rotation of #1 by 2: " << plaintextRot2 << std::endl;
  std::cout << "Right rotation of #1 by 1: " << plaintextRot3 << std::endl;
  std::cout << "Right rotation of #1 by 2: " << plaintextRot4 << std::endl;
}

