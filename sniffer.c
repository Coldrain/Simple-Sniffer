/*
*
*
* sudo apt-get install libpcap0.8-dev
*
* cc sniffer.c -lpcap -o testing
*
* -- Ornek filtreler
* ip                   	Capture all IP packets.
* tcp			Capture only TCP packets.
* tcp port 80		Capture only TCP packets with a port equal to 80.
* ip host 10.1.2.3	Capture all IP packets to or from host 10.1.2.3.\n
*
*/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>
#include <time.h>

int packet_no;
char errbuf[PCAP_ERRBUF_SIZE];
char *device_name;
char *network_address;    
char *network_mask;         
bpf_u_int32 pcap_network;   
bpf_u_int32 pcap_netmask;   

void callback(u_char *, const struct pcap_pkthdr *, const u_char *);
void is_root(char **);
void list_device(); 
void summary_information();

int main(int argc,char **argv)
{
	char packet_num_buff[16];
	char device_name_buff[16];

	pcap_t *handle;

	struct bpf_program fp;

	char filter_exp[] = "ip"; 


    	is_root(argv);
	list_device();

	printf("\nEnter the interface NAME or Press [Enter] key - default(%s) : ", pcap_lookupdev(errbuf));
	fflush(stdout);

    	fgets(device_name_buff, sizeof(device_name_buff)-1, stdin);
    	device_name_buff[strlen(device_name_buff)-1] = '\0';

    	if(strlen(device_name_buff) < 2)
        	device_name = pcap_lookupdev(errbuf);

    	printf("Enter the number of packet(s) which you want to capture - default(100): ");
    	fflush(stdout);

	    fgets(packet_num_buff, sizeof(packet_num_buff)-1, stdin);
    	packet_num_buff[strlen(packet_num_buff)-1] = '\0';

	packet_no = atoi(packet_num_buff);

    	if(packet_no == 0)
        	packet_no = 100;

    	if(strlen(device_name))
	{
		printf("\n ---You opted for device [%s] to will capture [%d] packets---\n",device_name, (packet_no));
	}
    	else
    	{
        	printf("\n[%s]\n", errbuf);
        	exit(1);
    	}


    	if (pcap_lookupnet(device_name, &pcap_network, &pcap_netmask, errbuf) == -1)
    	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device_name, errbuf);
		exit(1);
	}


    	handle = pcap_open_live(device_name, BUFSIZ, 1, 0, errbuf);

    	if(handle == NULL)
    	{
        	printf("pcap_open_live() failed due to [%s]\n", errbuf);
        	exit(1);
    	}


    	if(pcap_compile(handle, &fp, filter_exp, 0, pcap_network) == -1)
    	{
        	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        	exit(1);
    	}


    	if(pcap_setfilter(handle, &fp) == -1)
    	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        	exit(1);
    	}
    	
    	summary_information();
 
    	pcap_loop(handle, packet_no, callback, NULL);

    	printf("\nDone with packet sniffing!\n");
    	return 0;
}



/* ############################################################ */

void is_root(char ** pro_name)
{
    if (getuid() != 0)
    {
    printf("\n Usage: sudo %s  \n\n", pro_name[0]);

        exit(1);
    }
}

/* ############################################################ */

void list_device()
{
    int count = 0;
    pcap_if_t *alldevs, *device;

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"\nError in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

    printf("\nHere is a list of available devices on your system:\n\n");

	for(device=alldevs; device; device=device->next)
	{
		printf("%d. %-7s", ++count, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available for this device)\n");
	}

}

/* ############################################################ */

void summary_information()
{
    struct in_addr addr;
    addr.s_addr = pcap_network;
    network_address = inet_ntoa(addr);
    if(network_address == NULL)
    {
        perror("inet_ntoa");
        exit(1);
    }
    printf("+--------------------------------------------------------------+\n");
    printf("| Interface: %-20s                              |\n",device_name);
    printf("| Network:   %-20s                              |\n",network_address);
    addr.s_addr = pcap_netmask;
    network_mask = inet_ntoa(addr);

    if(network_mask == NULL)
    {
        perror("inet_ntoa");
        exit(1);
    }
    printf("| Netmask:   %-20s                              |\n",network_mask);
    printf("+--------------------------------------------------------------+\n");
}

/* ############################################################ */

void callback(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    int i = 0;
    static int count = 0;

    FILE *logp;

    if((logp = fopen("Logfile.txt","a")) == NULL)
    {
        perror("");
        exit(1);
    }
    time_t mytime;
    mytime = time(NULL);

    printf("\r");
    fflush(stdout);
    printf("Captured %d packets", ++count);
    fprintf(logp, "Packet No: %-6d ", count);   
    fprintf(logp, "Recieved Packet Size: %-6d Date: ", pkthdr->len);   
    fprintf(logp, ctime(&mytime));                
    for(i = 0; i < pkthdr->len; i++)
    {
        if(isprint(packet[i]))               
            fprintf(logp, "%c",packet[i]);          
        else
            fprintf(logp, ".",packet[i]);          
    }
    fprintf(logp, "\n#########\n\n");

    fclose(logp);


}
