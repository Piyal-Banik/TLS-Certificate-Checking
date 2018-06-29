//Name:Piyal Banik Student Id: 800602

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

//declaration of helper functions
int basic_checking(X509 *cert, char *url);
int time_validation(X509 *cert);
int domainName_validation(X509 *cert, char *url);
int advance_checking(X509 *cert);
int rsa_key_length_check(X509 *cert);
int basic_constraints_check(X509 *cert);
int extended_key_usage_check(X509 *cert);
char* get_extnsion_objects(X509 *cert, int NID);
int subject_alternative_name_check(X509 *cert, char* url);
int wildcard_validation(char *url, char *subjectCn);


int main(int argc, char *argv[]){
  
  FILE *fptr,*fptw;  //file pointers to read and write
  char buffer[255];  //contains each line from the read file

  BIO *certificate_bio = NULL;
    X509 *cert = NULL;

    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    //open the files
    fptr = fopen(argv[argc-1],"r");
    fptw = fopen("output.csv", "w");
    
    //get each line from the read file and process it accordingly
    while(fgets(buffer, 255, fptr)){
      char *cert_name = strtok(buffer,",");
      char *url = strtok(NULL,",\n");
      
      //create BIO object to read certificate
      certificate_bio = BIO_new(BIO_s_file());
      
      //Read certificate into BIO
      if (!(BIO_read_filename(certificate_bio, cert_name)))
      {
          fprintf(stderr, "Error in reading cert BIO filename");
          exit(EXIT_FAILURE);
      }
      if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
      {
          fprintf(stderr, "Error in loading certificate");
          exit(EXIT_FAILURE);
      }

      //cert contains the x509 certificate and can be used to analyse the certificate

      //performs Part B Basic Certificate Checking from the specification
      int basic = basic_checking(cert,url);

      //performs Part C Advanced Certificate Checking from the specification
      int advance = advance_checking(cert);

      //write onto the output file
      if(basic > 0 && advance > 0)
          fprintf(fptw, "%s,%s,%d\n",cert_name,url,1);
        else
          fprintf(fptw, "%s,%s,%d\n",cert_name,url,0);
    }

    fclose(fptr);
    fclose(fptw);
    BIO_free_all(certificate_bio);
    X509_free(cert);
    exit(0);
}

//function performing Part B : Basic Certificate Checking from the specification
int basic_checking(X509 *cert, char *url){
  int time_valid = time_validation(cert);  //time validation 
  int domainName_valid = domainName_validation(cert,url);  //domain name validation
  return time_valid && domainName_valid;
}

//function correctly validates time frame of the certificate 
int time_validation(X509 *cert){
  
  int pday,psec;
  time_t rawtime;
    ASN1_TIME *current_time = NULL;
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);

    time ( &rawtime );
    ASN1_TIME_set(current_time,  rawtime);  // this sets the current date
    
    //checks whether certificate can be used on the current time
    ASN1_TIME_diff(&pday, &psec,not_before,current_time);
    if(pday <= 0  || psec <= 0){
      return 0;
    }

    //checks expiry date of the certificate
    ASN1_TIME_diff(&pday, &psec,current_time,not_after);
    if(pday <= 0  || psec <= 0){
      return 0;
    }

    return 1;
}

//this function Correctly validates domain name in Common Name
int domainName_validation(X509 *cert, char *url){
  X509_NAME *subjectName = X509_get_subject_name(cert); ;
    char  subjectCn[256]; 
    X509_NAME_get_text_by_NID(subjectName, NID_commonName, subjectCn, 
      sizeof(subjectCn));  
    //if domain name does not match the given URL then check for wildcard or SAN
    if(strcmp(subjectCn,url)!=0){
        return wildcard_validation(url,subjectCn) || subject_alternative_name_check(cert,url);
    }
    free(subjectName);
    return 1;
}

//function correctly validating wildcard 
int wildcard_validation(char *url, char *subjectCn){
  int i,j = 0;
  for(i = 0; url[i] != '\0'; i++){
    //if subjectCn contains a "*" then skip part of the url until "." is found
    if(subjectCn[j] == '*'){
      while(url[i] != '.'){
        i++;
      }
        j++;
    }
    //if subjectCn charater doesn't match url character then return 0
    else if(subjectCn[j] != url[i]){
      return 0;
    }
        j++;
  }
  return 1;
}

//function correctly validating subject alternative name
int subject_alternative_name_check(X509 *cert, char *url){

  char *buf;
  char *dns;
  char *san;
  buf = get_extnsion_objects(cert, NID_subject_alt_name);
    
  //if subject alternative name is present check for similarity with url or wildcard of san
    if(buf){
      dns = strtok(buf, ", ");
      while (dns != NULL) {
        //following two lines skips "dns:" character from returned string
        san = strtok(dns,":");
          san = strtok(NULL,"");

          //if SAN doesn't match url check for wildcard of SAN
        if(strcmp(san,url)!=0){
          if(wildcard_validation(url,san)){
                return 1;      
          }
        }
        else{
          return 1;
        }
        dns = strtok(NULL, ", "); //gives next SAN
    }
  }
  return 0;
}

//function performing Part C : Advanced Certificate Checking from the specification
int advance_checking(X509 *cert){
  
  int size_check = rsa_key_length_check(cert);  //validates minimum RSA key length check
  int basic_constraints = basic_constraints_check(cert);  //BasicConstraints includes check
  int extended_key = extended_key_usage_check(cert); // Enhanced Key Usage check
  return size_check && basic_constraints && extended_key;
}

//function Correctly validates minimum RSA key length of 2048 bits
int rsa_key_length_check(X509 *cert){
  
  EVP_PKEY * public_key = X509_get_pubkey(cert);
  RSA *rsa_key = EVP_PKEY_get1_RSA(public_key);
  int key_length = RSA_size(rsa_key);  //size returned in bytes
  key_length = key_length * 8;  //converted to bits
  if(key_length < 2048){
    return 0;
  }
  RSA_free(rsa_key);
  return 1;
}

//function Correctly validates BasicConstraints includes â€œCA:FALSEâ€
int basic_constraints_check(X509 *cert){
  
  BASIC_CONSTRAINTS *bs;
  if ((bs = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL))) {
        if (bs->ca){
          return 0;
        }
    }
    return 1;

}

//function Correctly validates Enhanced Key Usage includes â€œTLS Web Server Authenticationâ€
int extended_key_usage_check(X509 *cert){

    char *buf = get_extnsion_objects(cert, NID_ext_key_usage);
    char *pch = strstr(buf, "TLS Web Server Authentication");
    if(pch){
      return 1;
    }
    return 0;
}

//function returning value contained by an extension with the hep if NID
//Acknowledgement: certexample.c given to us by Chris Culnane
char* get_extnsion_objects(X509 *cert, int NID){
  
  X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID, -1));
    if(!ex){
      return NULL;
    }
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);

  char buff[1024];
    OBJ_obj2txt(buff, 1024, obj, 0);
    BUF_MEM *bptr = NULL;
    char *buf = NULL;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, ex, 0, 0))
    {
        fprintf(stderr, "Error in reading extensions");
    }
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    //bptr->data is not NULL terminated - add null character
    buf = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';
    BIO_free_all(bio);
    return buf;
}





