#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/asn1t.h>
#include <stdlib.h>
int main(){
	char buf[] = "dns:sbc dns:abc dns:asd";
	char *url = "abc";
	char *dns;
   printf("aa\n");
  		dns = strtok(buf, " ");
  		while (dns != NULL) {
  			char *san;
        printf("%s\n",dns);
  			memcpy( san, &dns[4], strlen(dns)-1);
			san[strlen(san)-1] = '\0';
			printf("%s ",san);
  			if(strcmp(san,url)!=0){
  				//if(wildcard_validation(url,san)){
  					//return 1;
  				//}
  			}
  			else{
  				//return 1;
  			}
  			san = strtok(NULL, " ");
		}
}
