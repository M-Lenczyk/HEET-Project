# HEET-Project
Homomorphic Encryption Efficiency Testing Project
# Wprowadzenie
H.E.E.T Project - to projekt mający na celu ewaluację wydajnościową szyfrowania homomorficznego w porównaniu z tradycyjnym szyfrowaniem blokowym. W ramach projektu zmierzone i porównane zostały m.in. czasy tworzenia zaszyfrowanego zbioru danych oraz ich zajętość miejsca. Projekt został wykonany w języku C++, z wykorzystaniem WSL i systemu Ubuntu 22.04 . Jako bibliotekę szyfrowania homomorficznego zdecydowano się na rozwiązanie PALISADE <link> , w przypadku szyfrowania niehomomorficznego zdecydowano się na algorytm Advanced Encryption Standard z biblioteki Crypto++ <link>.

# Instalacja 

## PALISADE

W celu zainstalowania biblioteki szyfrowania homomorficznego PALISADE wymagany jest CMake. Szczegółowe instrukcje instalacji w zależności od wybranego systemu operacyjnego znajdują się na oficjalnej stronie projektu PALISADE. Zalecamy jednak stosowanie Linuxa. Szczegółowy proces instalacji biblioteki dla systemu Linux wykorzystany do tego projektu znajduje się pod adresem: <link>

Po pomyślnej weryfikacji instalacji PALISADE i Crypto++ i uruchomienia przykładowego projektu dołączonego do biblioteki należy pobrać repozytorium projektu. W zależności od preferencji użytkownika projekt może znajdować się bezpośrednio w katalogu głównym biblioteki bądź osobno, w pliku CMakeLists.txt <link do pliku> znajdują się adnotacje automatycznie znajdujące bibliotekę.

## Crypto++

Do Crypto++ również można zastosować CMake, jednak w naszym przypadku zdecydowaliśmy się na rozwiązanie w postaci *apt-get*.
Szczegółowe instrukcje instalacji Crypto++ znajdują się pod adresem: https://www.cryptopp.com/wiki/Linux.
W przypadku korzystania z `apt-get` należy sprawdzić wersję paczki Crypto++ dla danej dystrybucji (wymagana jest wersja libcrypto++8). W przypadku starszej wersji paczki, należy zaktualizować system. Szczegóły instalacji dla metody *apt-get* znajdują się pod adresem: https://www.cryptopp.com/wiki/Linux#apt-get

# Uruchamianie

Uruchomienie poszczególnych skryptów wykonuje się następującymi komendami:

Uruchomienie programu dla szyfrowania homomorficznego

```
    mkdir build && cd build
    cmake ..
    make
    ./main
```
Wynikiem uruchomienia jest komunikat w konsoli prezentujący czas 
Uruchomienie programu dla tradycyjnego szyfrowania AES

```
g++ -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -o AesOutput aes.cpp -lcryptopp
./AesOutput
```

# Schemat Eksperymentu

W ramach eksperymentu zrealizowane zostało

1. Ewaluacja wydajnościowa poszczególnych operacji homomorficznych
3. Ewaluacja wydajnościowa procesu szyfrowania/deszyfrowania zbioru danych szyfrowaniem homomorficznym
4. Ewaluacja wydajnościowa procesu szyfrowania/deszyfrowania zbioru danych szyfrowaniem AES
5. Ewaluacja zajętości miejsca zbioru danych zaszyfrowanego za pomocą szyfrowania homomorficznego
6. Ewaluacja zajętości miejsca zbioru danych zaszyfrowanego za pomocą szyfrowania AES
7. Porównanie wydajności oraz zajętości miejsca obu metod szyfrowania

Na potrzeby testów utworzony został utworzony zbiór danych składający z 1 000 000 wektorów o rozmiarze 10, przechowujący liczby z zakresu <1;10>.  

## Ewaluacja wydajnościowa szyfrowania homomorficznego z wykorzystaniem biblioteki PALISADE

Na potrzeby testów PALISADE ustaliliśmy 5 wariantów kombinacji operacji homomorficznych:

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

Zostały przeprowadzone następujące eksperymenty w celu ewaluacji wydajnościowej poszczególnych operacji homomorficznych:

   - sprawdzenie zależności wyłącznie od parametru numMults (Eksperyment 1)
   - sprawdzenie zależności wyłącznie od parametru dist (Eksperyment 2)
   - sprawdzenie zależności wyłącznie od parametru securityLevel (Eksperyment 3)
   - sprawdzenie zależności wyłącznie od parametru modulus (Eksperyment 4)
   - sprawdzenie zależności od parametrów modulus i numMults (Eksperyment 5)
   - sprawdzenie zależności od parametrów modulus i dist (Eksperyment 6)
   - sprawdzenie zależności od parametrów dist i numMults (Eksperyment 7)
   - sprawdzenie zależności od parametrów securityLevel i numMults (Eksperyment 8)
   - sprawdzenie zależności od parametrów securityLevel i modulus (Eksperyment 9)

Każdy eksperyment brał jeden z zestawów parametrów i realizował wszystkie wymienione warianty.

W każdym eksperymencie mierzony był czas:

   - avg encryption - średni czas zaszyfrowania wartości ze zbioru danych równy: T/N gdzie T oznacza czas zaszyfrowania pełnego datasetu, N liczba elementów w zbiorze danych
   - decryption - czas deszyfracji pełnego zbioru danych
   - key generation - czas potrzebny do utworzenia pary kluczy do zaszyfrowania danych źródłowych
   - key gen 4 HME - czas potrzebny do generacji kluczy na podstawie prywatnego klucza źródłowego umożliwiających operację mnożenia homomorficznego.
   - total encryption - całkowity czas potrzebny do otrzymania zaszyfrowanego zbioru danych
   - total hom. operations - czas trwania wybranego wariantu operacji homomorficznych

## Ewaluacja wydajnościowa szyfrowania AES z wykorzystaniem biblioteki Crypto++

W przypadku AES jedynym parametrem który należało wziąć pod uwagę była długość klucza. Odpowiednikiem długości klucza w przypadku PALISADE był parametr securityLevel, stąd w celu adekwatnego porównania należy wziąć zbiór danych zaszyfrowany kluczem o takiej samej długości.

