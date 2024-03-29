# H.E.E.T - Homomorphic Encryption Efficiency Testing Project
# Wprowadzenie
H.E.E.T Project - to projekt mający na celu ewaluację wydajnościową szyfrowania homomorficznego w porównaniu z tradycyjnym szyfrowaniem blokowym. W ramach projektu zmierzone i porównane zostały m.in. czasy tworzenia zaszyfrowanego zbioru danych oraz ich zajętość miejsca. Projekt został wykonany w języku C++, z wykorzystaniem WSL i systemu Ubuntu 22.04 . Jako bibliotekę szyfrowania homomorficznego zdecydowano się na rozwiązanie [PALISADE](https://gitlab.com/palisade/palisade-release), w przypadku szyfrowania niehomomorficznego zdecydowano się na algorytm Advanced Encryption Standard z biblioteki [Crypto++](https://www.cryptopp.com/wiki/Main_Page).

# Instalacja 

## PALISADE

W celu zainstalowania biblioteki szyfrowania homomorficznego PALISADE wymagany jest CMake. Szczegółowe instrukcje instalacji w zależności od wybranego systemu operacyjnego znajdują się na oficjalnej stronie projektu PALISADE. Zalecamy jednak stosowanie Linuxa. Szczegółowy proces instalacji biblioteki dla systemu Linux wykorzystany do tego projektu znajduje się [tutaj](https://www.cryptopp.com/wiki/Linux).

Po pomyślnej weryfikacji instalacji PALISADE i Crypto++ i uruchomienia przykładowego projektu dołączonego do biblioteki należy pobrać repozytorium projektu. W zależności od preferencji użytkownika projekt może znajdować się bezpośrednio w katalogu głównym biblioteki bądź osobno, w pliku [CMakeLists.txt](https://github.com/M-Lenczyk/HEET-Project/blob/80b7cc12bb4bd1549962efa5a40b665ac9ec36db/CMakeLists.txt) znajdują się adnotacje automatycznie znajdujące bibliotekę.

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
Wynikiem uruchomienia jest komunikat w konsoli prezentujący czas wykonania poszczególnych operacji homomorficznych, utworzenia zaszyfrowanego zbioru danych, czas deszyfracji zbioru danych oraz zajmowane przez niego miejsce.

Uruchomienie programu dla tradycyjnego szyfrowania AES

```
g++ -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -o AesOutput aes.cpp -lcryptopp
./AesOutput
```
Wynikiem uruchomienia jest komunikat w konsoli prezentujący czas utworzenia zaszyfrowanego zbioru danych dla klucza o określonej długości oraz rozmiar tego zaszyfrowanego zbioru.

# Schemat Eksperymentu

W ramach eksperymentu zrealizowane zostało

1. Ewaluacja wydajnościowa poszczególnych operacji homomorficznych
3. Ewaluacja wydajnościowa procesu szyfrowania/deszyfrowania zbioru danych szyfrowaniem homomorficznym
4. Ewaluacja wydajnościowa procesu szyfrowania/deszyfrowania zbioru danych szyfrowaniem AES
5. Ewaluacja zajętości miejsca zbioru danych zaszyfrowanego za pomocą szyfrowania homomorficznego
6. Ewaluacja zajętości miejsca zbioru danych zaszyfrowanego za pomocą szyfrowania AES
7. Porównanie wydajności oraz zajętości miejsca obu metod szyfrowania

Na potrzeby testów utworzony został utworzony zbiór danych składający z 1 000 000 wektorów o rozmiarze 10, przechowujący liczby z zakresu <1;10>. Mały zakres poszczególnych wartości jest spowodowany dużą liczbą operacji homomorficznych który może spodować utworzenie wartości większych niż ustalona górna granica definiowana przez parametr modulus dla szyfrowania homomorficznego.   

## Ewaluacja szyfrowania homomorficznego z wykorzystaniem biblioteki PALISADE

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

## Ewaluacja szyfrowania AES z wykorzystaniem biblioteki Crypto++

W przypadku AES jedynym parametrem który należało wziąć pod uwagę była długość klucza. Odpowiednikiem długości klucza w przypadku PALISADE był parametr securityLevel, stąd w celu adekwatnego porównania należy wziąć zbiór danych zaszyfrowany kluczem o takiej samej długości.

# Wyniki eksperymentu

Wyniki eksperymentu są dostępne w postaci [raportu](https://m-lenczyk.github.io/HEET-Project/plotRes.html). Raport jest również dostępny w [postaci rmarkdown](https://github.com/M-Lenczyk/HEET-Project/blob/8f256cd4547db8d557ed0dbe26ca93b26c6d8812/plotRes.Rmd) umożliwiający ewentualne modyfikacje wizualizacji i generowanie do postaci html. Raport ten składa się z trzech części.

Część pierwsza zawiera wykresy przedstawiające otrzymane czasy przetwarzania dla eksperymentów 1-4 dotyczących ewaluacji wydajnościowej (czasowej) szyfrowania homomorficznego dla poszczególnych parametrów, celem określenia jak zmiana wyłącznie jednego parametru wpłynie na ogólny czas całego procesu szyfrowania homomorficznego i poszczególnych pojedynczych operacji homomorficznych.

Część druga zawiera wykresy przedstawiające otrzymane czasy przetwarzania dla eksperymentów 5-6 dotyczących ewaluacji wydajnościowej (czasowej) szyfrowania homomorficznego dla kombinacji parametrów.

Część trzecia zawiera porównanie czasów przetwarzania oraz rozmiarów danych dla zbioru danych zaszyfrowanego z użyciem szyfrowania homomorficznego oraz AES'a dla trzech długości klucza (128,192,256). Ponieważ PALISADE wymaga określenia parametrów celem umożliwenia realizacji procesu szyfrowania homomorficznego, porównane zostały 3 przypadki:

- def - oznaczający scenariusz domyślny, gdzie wartości parametrów są domyślne zgodne z [standardem](https://projects.csail.mit.edu/HEWorkshop/HomomorphicEncryptionStandard2018.pdf) i mieszanego wariantu operacji homomorficznych.

- best case- oznaczający pojedynczy najlepszy możliwy scenariusz, optymalnym doborem parametrów i wariantu cechującego się najkrótszym czasem przetwarzania. W tym przypadku jest to wariant składający się wyłącznie z samych operacji dodawania.

- worst case - oznaczający pojedynczy najgorszy możliwy scenariusz, gdzie wybrano najdłuższy klucz, gigantyczny modulus oraz dużą liczbę operacji mnożeń, które są najbardziej wymagającą z wszystkich operacji homomorficznych. 

# Konkluzja

Analizując wykresy dotyczące poszczególnych parametrów wykorzystywanych przez PALISADE do szyfrowania homomorficznego, można jednoznacznie stwierdzić że największy wpływ ma zmiana parametru numMults czyli maksymalna głębokość mnożeń. Zauważono również pozytywną korelację między czasem a parametrem securityLevel. Zwiększanie wartości tego parametru, jednocześnie zwiększało średni czas pojedynczego szyfrowania i generowania kluczy dla operacji homomorficznych. Podobną zależność zauważono dla parametru modulus. W przypadku parametru dist, zauważono średnio dłuższe czasy szyfrowania i generowania operacji homomorficznych dla małych wartości (tj. < 5). Warto również tutaj dodać że zwiększanie wartości tego parametru powodowało iż czasy były bardziej "skupione" tj. zbliżone do siebie, niż w przypadku małych wartości parametru dist.

Wykresy czasów przetwarzania jednoznacznie wskazują iż szyfrowanie homomorficzne cechuje się większym narzutem czasowym, co było oczywiste ze względu na stosowanie dodatkowych operacji mających na celu zwiększenie bezpieczeństwa i jednoczesne umożliwienie wykonywania operacji na zaszyfrowanym zbiorze. Narzut czasowy jest bardzo duży - gdy pojedyncze czasy szyfrowania i deszyfrowania dla AES są średnio na poziomie kilku mikrosekund, to dla szyfrowania homomorficznego czas ten wzrasta do kilkudziesięciu a nawet w niektórych przypadkach do kilkaset milisekund.

W kwestii rozmiaru, nasz zbiór zaszyfrowany homomorficznie posiada średnio rozmiar około 1 MB, natomiast zbiór zaszyfrowany za pomocą AES posiada rozmiar około 0.1kB co daje nam to narzut rzędu około 10 000. Dodatkowo rozmiar danych dla szyfrowania homomorficznego silnie zależy od wybranych parametrów. Dla scenariusza worst-case rozmiar danych sięga nawet 10MB. W tym wypadku należy mieć na uwadze iż lekka zmiana niektórych parametrów (np. numMults) może diametralnie zmienić wynik końcowy.

Ze względu na możliwość wykonywania operacji na zaszyfrowanych danych, szyfrowanie homomorficzne jest wykorzystywane w sytuacjach gdzie np. pobieranie i rozszyfrowywanie całego zbioru danych w celu wykonania operacji jest nieopłacalne. Takimi sytuacjami może być uruchomienie modelu treningowego na poufnych danych albo wykonanie zaszyfrowanego zapytania do chmury. 

Podsumowując, można stwierdzić że szyfrowanie homomorficzne jest wysoce niewydajne pod względem wydajnościowym zarówno w aspekcie zajmowanego miejsca jak i dodatkowego narzutu czasowego i nie będzie alternatywą dla szyfrowania klasycznego. Jednakże mając na uwadze iż są to dwa odrębne rodzaje szyfrowania, szyfrowanie homomorficzne mimo swoich wad potrafi być wykorzystywane w miejscach gdzie szyfrowanie tradycyjne będzie nieadekwatne. 

# Referencje

- PALISADE Manual: https://gitlab.com/palisade/palisade-development/blob/master/doc/palisade_manual.pdf
- PALISADE Home: https://gitlab.com/palisade/palisade-release
- PALISADE Webinars: https://palisade-crypto.org/webinars/
- PALISADE Library: https://palisade.gitlab.io/palisade-development/classes.html
- Crypto++ Home: https://www.cryptopp.com/wiki/Main_Page
- Homomorphic Encryption Standard: https://eprint.iacr.org/2019/939.pdf


