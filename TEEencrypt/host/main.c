/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char** argv)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[86] = {0,};
	char ciphertext[128] = {0,};
	char *option = argv[1];
	char *algorithm;
	int len=86;
	int c_len = 128;
	int enc_key, dec_key;
	FILE *fp, *fi;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, 						 TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	
	
	//encode
	if(strcmp(option, "-e") == 0){	
		algorithm = argv[3];
		//Caesar
		if(strcmp(algorithm, "Caesar") == 0){
	
			printf("========================Caesar Encryption========================\n");
			fp = fopen(argv[2],"r");
			fgets(plaintext, sizeof(plaintext), fp);
			printf("Plaintext: %s\n", plaintext);
			memcpy(op.params[0].tmpref.buffer, plaintext, len);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
	
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);

			memcpy(ciphertext, op.params[0].tmpref.buffer, len);
			printf("Ciphertext : %s\n", ciphertext);

			fp = fopen("caesar_ciphertext.txt","w");
			fputs(ciphertext, fp);

			fp = fopen("enc_key.txt", "w");
			fprintf(fp, "%d\n", op.params[1].value.a);
			fclose(fp);

		}
		//RSA
		else{
			
		}

	}
	

	//decode
	else if(strcmp(option,"-d") == 0){
	
		algorithm = argv[3];
		//Caesar
		if(strcmp(algorithm, "RSA") != 0) {
			algorithm = argv[4];
		
			printf("========================Caesar Decryption========================\n");
			fi = fopen(argv[2], "r");
			fgets(ciphertext, sizeof(ciphertext), fi);
			fflush(fi);

			fi = fopen(argv[3],"r");
			fscanf(fi, "%d", &dec_key);
			printf("dec_key: %d\n", dec_key);
			printf("Ciphertext : %s\n", ciphertext);

			memcpy(op.params[0].tmpref.buffer, ciphertext, len);
			op.params[1].value.a = dec_key;

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_DEC, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,&err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
	
			memcpy(plaintext, op.params[0].tmpref.buffer, len);
			printf("Plaintext : %s\n", plaintext);
	
			fi = fopen("caesar_plaintext.txt","w");
			fputs(plaintext, fi);
			fclose(fi);
			
		}

		//RSA
		else{
		}

	}

	//except
	else{
		printf("wrong option\n");	
	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
