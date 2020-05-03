# IPK - ZETA
Auror: Šimon Sedláček, xsedla1h

## Struktura projetkového adresáře
V korenovem adresari projektu se nachazi krome tohoto souboru (README.md) a souboru s
dokumentaci (manual.pdf) soubor Makefile a slozka se zdrojovymi soubory src/.
Slozka src/ obsahuje soubory main.cpp, resources.cpp, resources.hpp,
sniffer.cpp a sniffer.hpp.

## Kompilace a spuštění snifferu
Pro kompilaci projektu proveďte příkaz make v kořenovém adresáři projektu. Po přeložení se v kořenovém adresáři objeví spustitelný soubor s názvem ipk-sniffer. Program je poté nutné spouštět s administrátorskými privilegii, jinak mu bude odepřen přístup k síťovým rozhraním.

Priklad spusteni programu:

   sudo ./ipk-sniffer -i ens3 -p 22 -n 10


## Popis programu
Sniffer využívá knihovny libpcap k připojení na konkrétní síťové zařízení, na kterém jsou
zachytávány pakety. Každý zachycený paket je postupně zpracováván sérií funkcí a následně
jsou informace o paketu společně s obsahem vypsány na výstup.

Sniffer zpracovává pouze Ethernetové tcp/udp pakety s IPv4/IPv6 sitovym protokolem.

## Omezení překladu IPv6 adres
Sniffer nepřekládá ipv6 adresy na doménová jména, toto funguje pouze pro ipv4 adresy. Tento aspekt je blíže popsán v dokumentaci.


Podrobnejsi popis reseni najdete v dokumentaci manual.pdf.
