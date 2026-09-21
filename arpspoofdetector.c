#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

int main() {

    int socket_fd;

    //Socket é uma interface que permite ao programa se comunicar através da rede.
    //AF_PACKET permite trabalhar diretamente com frames da camada de enlace.
    //// SOCK_RAW: Socket bruto que permite acesso direto à camada de rede (ex: IP/ICMP).
    // Permite criar ou ler cabeçalhos customizados, ignorando o TCP/UDP padrão.
    // Geralmente requer privilégios de administrador (root).
    /*
    * ETH_P_ALL (0x0003) - Linux Network Protocol Constant
    * -------------------------------------------------------------
    * Utilizado em sockets raw (AF_PACKET) para capturar e monitorar
    * TODOS os pacotes Ethernet de entrada e saída, independentemente
    * do protocolo de rede (IP, ARP, etc.).
    *
    * Requer privilégios de superusuário (root / CAP_NET_RAW).
    * Comumente usado em sniffers de rede e ferramentas de análise.
    */

    // htons(ETH_P_ALL): Garante a conversão do identificador de protocolo (0x0003)
// do formato do processador (Host Byte Order) para o formato padrão da rede
// (Network Byte Order / Big-Endian), evitando erros em arquiteturas Little-Endian (x86/x64).

/*
 * CONVERSÃO DE ENDIANNESS (htons + ETH_P_ALL):
 * - Host (PC/CPU x86_64/ARM): Utiliza padrão Little-Endian (bytes invertidos).
 * - Network (Rede): Exige estritamente o padrão Big-Endian.
 * - htons(): Corrige a ordem dos bytes para que o kernel Linux entenda o 
 *   identificador do protocolo corretamente, evitando falhas na captura.
 */

    socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (socket_fd == -1) {
        perror("socket");
        return 1;
    }

    printf("Raw socket criado com sucesso!\n");

    unsigned char buffer[65536];
    while(1){
        int tamanho = recvfrom(
            socket_fd,
            buffer,
            sizeof(buffer),
            0,
            NULL,
            NULL
        );

        if (tamanho == -1) {
            perror("recvfrom");
            return 1;
        }

        //printf("Recebemos um frame de %d bytes!\n", tamanho);

        // Interpreta o início do buffer como um cabeçalho Ethernet (struct ethhdr).
        // O ponteiro aponta para a mesma região de memória, sem copiar os dados.
        struct ethhdr *ethernet = (struct ethhdr *) buffer;

        /*printf(
        "%02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X\n ",
        ethernet->h_source[0],
        ethernet->h_source[1],
        ethernet->h_source[2],
        ethernet->h_source[3],
        ethernet->h_source[4],
        ethernet->h_source[5],
        ethernet->h_dest[0],
        ethernet->h_dest[1],
        ethernet->h_dest[2],
        ethernet->h_dest[3],
        ethernet->h_dest[4],
        ethernet->h_dest[5]
    );
    */

    char buffer_source_ip[INET_ADDRSTRLEN]; //Cinstante para o tamanho de um ip em formato textual
    char buffer_dest_ip[INET_ADDRSTRLEN];
    if (ntohs(ethernet->h_proto) == ETH_P_IP) { //Converte o campo h_proto de struct ethhdr que está em Network Byte Order para o formato de maquina
        struct iphdr *ip = (struct iphdr *) (buffer+14); // Typecast de buffer + 14, que aponta para o início do cabeçalho IPv4 após os 14 bytes do cabeçalho Ethernet, para struct iphdr, que representa a estrutura do cabeçalho IPv4.
        int tamanho_bytes_ipv4 = ip->ihl*4; // O campo IHL indica o tamanho do cabeçalho IPv4 em unidades de 32 bits (4 bytes); por isso, multiplicamos seu valor por 4 para obter o tamanho em bytes.
        inet_ntop(AF_INET, &ip->saddr, buffer_source_ip, sizeof(buffer_source_ip));
        inet_ntop(AF_INET, &ip->daddr, buffer_dest_ip, sizeof(buffer_dest_ip));
        if(ip->protocol == 1){
            printf("%s -> %s | PROTOCOL: %d | ICMP\n", buffer_source_ip, buffer_dest_ip, ip->protocol);
        }
    }       
    }
    return 0;
}
