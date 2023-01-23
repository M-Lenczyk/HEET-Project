# HEET-Project
Homomorphic Encryption Efficiency Testing Project
# Wprowadzenie
H.E.E.T Project - to projekt mający na celu ewaluację wydajnościową szyfrowania homomorficznego w porównaniu z tradycyjnym szyfrowaniem blokowym. W ramach projektu zmierzone i porównane zostały m.in. czasy tworzenia zaszyfrowanego zbioru danych oraz ich zajętość miejsca. Projekt został wykonany w języku C++, z wykorzystaniem systemu Ubuntu 22.04. Jako bibliotekę szyfrowania homomorficznego zdecydowano się na rozwiązanie PALISADE <link> , w przypadku szyfrowania niehomomorficznego zdecydowano się na Advanced Encryption Standard z biblioteki Crypto++ <link>.

# Instalacja
W celu zainstalowania biblioteki szyfrowania homomorficznego PALISADe wymagany jest CMake. Szczegółowe instrukcje instalacji znajdują się na oficjalnej stronie.

TODO
Po pomyślnej weryfikacji instalacji PALISADE i Crypto++ należy pobrać repozytorium projektu <link>
Uruchomienie poszczególnych skryptówwykonuje się następującymi komendami:

TODO

Compile HEET example:
```
    mkdir build && cd build
    cmake ..
    make
    ./main
```
TODO

Compile aes example:
```
g++ -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -o AesOutput aes.cpp -lcryptopp
./AesOutput
```
#Schemat eksperymentu
TODO
Na potrzeby testów ustaliliśmy 5 wariantów kombinacji operacji homomorficznych:

   - 10 x MUL - oznaczający 10 sekwencyjnych mnożeń
   - 10 x ADD - oznaczający 10 sekwencyjnych dodawań
   - 5x ADD + 5x MUL - oznaczający 5 sekwencyjnych dodawań, a następnie 5 sekwencyjnych mnożeń
   - 1x ADD + 1x MUL + ... - oznaczający naprzemienne realizowanie operacji dodawania a następnie mnożenia do momentu uzyskania sumarycznie 10 operacji
   - 3x ADD + 3x MUL + 4x ADD - oznaczający 3 sekwencyjne dodawania, następnie 3 sekwencyjne mnożenia, a następnie znowu 4 sekwencyjne dodawania.

Parametry które zostały wybrane i odpowiednio zmieniane na potrzeby testów są następujące:

   - modulus - modulo, odpowiednio duża liczba naturalna, określająca górną granicę obliczeń. PALISADE wykorzystuje ten parametr do wygenerowania reszty parametrów dla metod potrzebnych do realizacji operacji homomorficznych.
   - securityLevel - klasa oznaczająca wybrany poziom zabezpieczeń, oznacza również długość klucza. Może mieć ona wartość 128,192 lub 256.
    - dist - distribution parameter for Gaussian noise generation, docelowe odchylenie standardowe dla rozkładu błędów dla szumu Gaussowskiego.
    - numMults - oznacza największą możliwą "głębokość" operacji mnożeń. Może ale nie musi być równa liczbie operacji mnożeń. Np. x1*x2*x3*x4  możemy zapisać jako wyrażenie ((x1*x2)*x3)*x4 dla którego głębokość będzie wynosić 3, a dla (x1*x2)*(x3*x4) natomiast mamy głębokość równą 2.

Wybrane zostały następujące zestawy wartości parametrów:
- modulus: { 536903681, 400051, 321312269, 7672487, 821312234893, 921312236417 }
- securityLevel: { HEStd_128_classic, HEStd_192_classic, HEStd_256_classic }
- dist = { 3.2, 5.4, 8.2, 30.6, 1.7, 0.8, 0.2, 0.01, 0.001 }
- numMults = { 1,2,3,4,6,8,10,15,20 }

Zostały przeprowadzone następujące eksperymenty:

   - sprawdzenie zależności wyłącznie od parametru numMults.
   - sprawdzenie zależności wyłącznie od parametru dist.
   - sprawdzenie zależności wyłącznie od parametru securityLevel.
   - sprawdzenie zależności wyłącznie od parametru modulus


Każdy eksperyment brał jeden z zestawów parametrów i realizował wszystkie wymienione warianty.

W Każdym eksperymencie mierzony był czas:

   - avg encryption - średni czas zaszyfrowania wartości ze zbioru danych równy: T/N gdzie T oznacza czas zaszyfrowania pełnego datasetu, N liczba elementów w zbiorze danych
   - decryption - czas deszyfracji pełnego zbioru danych
   - key generation - czas potrzebny do utworzenia pary kluczy do zaszyfrowania danych źródłowych
   - key gen 4 HME - czas potrzebny do generacji kluczy na podstawie prywatnego klucza źródłowego umożliwiających operację mnożenia homomorficznego.
   - total encryption - całkowity czas potrzebny do otrzymania zaszyfrowanego zbioru danych
   - total hom. operations - czas trwania wybranego wariantu operacji homomorficznych

TODO TODO TODO

