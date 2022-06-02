#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "cryptoki_win32.h"

const char libraryPath[1000];
const unsigned int sessionsOpened = 0;
static HMODULE hModule = NULL;
static CK_FUNCTION_LIST_PTR pFunctions = 0;
static CK_SESSION_HANDLE hSession1;
static char pkcs11PIN[64];
// int slotID = 0;
int slotID = 1;
int err = 0;
// int setInitArgs = 1;
int setInitArgs = 0;
long createMutex = 0;
long destroyMutex = 0;
long lockMutex = 0;
long unlockMutex = 0;
long flags = 2;
long pReserved = 0;

int init();
int login();
void close();
void listKeys();

CK_OBJECT_CLASS getCLASS(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj);
CK_UTF8CHAR_PTR getLABEL(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj,
		CK_ULONG_PTR pulCount);
CK_BYTE_PTR getID(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj,
		CK_ULONG_PTR pulCount);

int main() {
	printf("starting p11query ...\n");
	if (init() == -1) {
		printf("Error initializing environment...\n");
	} else {
		printf("Initialized ...\n");
		if (login() == -1) {
			printf("Login failed... quiting ...\n");
			close();
			return -1;
		} else {
			printf("Login success ...\n");
			listKeys();
		}
	}
	printf("closing ...\n");
	close();
	return 0;
}

int init() {
	printf("Please enter libpath: \n");
	scanf("%s", libraryPath);
	printf("Libpath: %s\n", libraryPath);
	hModule = LoadLibrary(libraryPath);

	if (hModule == NULL) {
		printf("Invalid hModule\n");
		return -1;
	}

	CK_C_GetFunctionList pC_GetFunctionList = NULL;
	if ((pC_GetFunctionList = (CK_C_GetFunctionList) GetProcAddress((hModule),
			"C_GetFunctionList")) == NULL) {
		printf("GetFunctionList failed\n");
		return -1;
	}

	// Get addresses of all the remaining PKCS#11 functions
	err = pC_GetFunctionList(&pFunctions);
	if (err != CKR_OK) {
		printf("GetFunctionList err: %d\n", err);
		return -1;
	}

	// Initialize token	
	if (setInitArgs != 1) {
		err = pFunctions->C_Initialize(NULL);
		printf("C_Initialize without init args\n");
	} else {
		CK_C_INITIALIZE_ARGS InitArgs = { (CK_VOID_PTR) createMutex,
				(CK_VOID_PTR) destroyMutex, (CK_VOID_PTR) lockMutex,
				(CK_VOID_PTR) unlockMutex, flags, (CK_VOID_PTR) pReserved };
		err = pFunctions->C_Initialize(&InitArgs);
		printf("C_Initialize with init args\n");
	}
	if (err != CKR_OK) {
		printf("C_Initialize failed\n");
		return -1;
	}

	return 1;
}

int login() {
	printf("Please enter slot ID: \n");
	scanf("%d", &slotID);
	printf("Selected SlotID: %d\n", slotID);

	printf("PKCS #11 PIN: ");
	scanf("%s", pkcs11PIN);

	// Open session
	err = pFunctions->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION,
	NULL, NULL, &hSession1);
	if (err == CKR_OK) {
		printf("Opened session to CK_SESSION_HANDLE %ld ...\n", hSession1);
	} else {
		printf("Failed to C_OpenSession ...\n");
		return -1;
	}

	// Login session
	err = pFunctions->C_Login(hSession1, CKU_USER, (CK_UTF8CHAR*) pkcs11PIN,
			strlen(pkcs11PIN));
	if (err != CKR_OK) {
		printf("Failed to C_Login ...\n");
		return -1;
	} else {
		printf("Logged in to CK_SESSION_HANDLE %ld ...\n", hSession1);
	}

	return 1;
}

void listKeys() {
	CK_OBJECT_HANDLE object;
	CK_ULONG count = 0;
	CK_ULONG foundKeys = 0;
	char *label;
	CK_ULONG size = 0;
	unsigned char *id;

	// Begin search
	err = pFunctions->C_FindObjectsInit(hSession1, NULL, 0);
	if (err == CKR_OK) {
		// Searching
		printf("Begin key listing ...\n");

		while (1) {
			err = pFunctions->C_FindObjects(hSession1, &object, 1, &count);
			if (err != CKR_OK) {
				printf("ERR FindObjects: %d\n", err);
				pFunctions->C_FindObjectsFinal(hSession1);
				break;
			}

			if (count == 0) {
				break;
			}

			foundKeys++;

			printf("Found %ld ...\n", foundKeys);

			if ((label = getLABEL(hSession1, object, NULL)) != NULL) {
				printf("    label: %s\n", label);
				free(label);
			}

			CK_OBJECT_CLASS cls = getCLASS(hSession1, object);
			switch (cls) {
			case CKO_PUBLIC_KEY:
				printf("Public Key Class\n");
				break;
			case CKO_PRIVATE_KEY:
				printf("Private Key Class\n");
				break;
			case CKO_SECRET_KEY:
				printf("Secret Key Class\n");
				break;
			case CKO_CERTIFICATE:
				printf("Cert Class\n");
				break;
			case CKO_DATA:
				printf("Data Class\n");
				break;

				// PKCS #11 V3.0 spec only
				//case CKO_PROFILE:
				//printf("Profile Class\n");
				//break;

			default:
				printf("Unknown Class\n");
			}

			if ((id = getID(hSession1, object, &size)) != NULL && size) {
				unsigned int n;
				printf("    ID: ");
				for (n = 0; n < size; n++)
					printf("%02x", id[n]);
				printf("\n");
				free(id);
			}

		}
		printf("Finish key listing %ld keys...\n", foundKeys);
	} else {
		printf("Error found when listing keys ...\n");
	}

	// End search
	pFunctions->C_FindObjectsFinal(hSession1);
}

CK_OBJECT_CLASS getCLASS(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj) {
	CK_OBJECT_CLASS type = 0;
	CK_ATTRIBUTE attr = { CKA_CLASS, &type, sizeof(type) };
	CK_RV rv;

	rv = pFunctions->C_GetAttributeValue(sess, obj, &attr, 1);
	if (rv != CKR_OK)
		printf("Attribute Err: %ld\n", rv);
	return type;
}

CK_UTF8CHAR_PTR getLABEL(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj,
		CK_ULONG_PTR pulCount) {
	CK_ATTRIBUTE attr = { CKA_LABEL, NULL_PTR, 0 };
	CK_RV rv;
	CK_UTF8CHAR_PTR labelPtr;
	if (pulCount)
		*pulCount = 0;
	rv = pFunctions->C_GetAttributeValue(sess, obj, &attr, 1);
	if (rv == CKR_OK) {
		if (attr.ulValueLen == (CK_ULONG)(-1)) {
			printf("Value len == -1\n");
			return NULL;
		}
		labelPtr = (CK_UTF8CHAR_PTR) malloc(attr.ulValueLen);
		attr.pValue = labelPtr;
		rv = pFunctions->C_GetAttributeValue(sess, obj, &attr, 1);
		if (attr.ulValueLen == (CK_ULONG)(-1)) {
			printf("Value len == -1\n");
			free(attr.pValue);
			return NULL;
		}
		if (pulCount)
			*pulCount = attr.ulValueLen / sizeof(char);
	} else if (rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		printf("Attribute Err: %ld\n", rv);
	}
	return (CK_UTF8CHAR_PTR) attr.pValue;
}

CK_BYTE_PTR getID(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj,
		CK_ULONG_PTR pulCount) {
	CK_ATTRIBUTE attr = { CKA_ID, NULL_PTR, 0 };
	CK_RV rv;
	CK_UTF8CHAR_PTR labelPtr;
	if (pulCount)
		*pulCount = 0;
	rv = pFunctions->C_GetAttributeValue(sess, obj, &attr, 1);
	if (rv == CKR_OK) {
		if (attr.ulValueLen == (CK_ULONG)(-1)) {
			printf("Value len == -1\n");
			return NULL;
		}
		labelPtr = (CK_UTF8CHAR_PTR) malloc(attr.ulValueLen);
		attr.pValue = labelPtr;
		rv = pFunctions->C_GetAttributeValue(sess, obj, &attr, 1);
		if (attr.ulValueLen == (CK_ULONG)(-1)) {
			printf("Value len == -1\n");
			free(attr.pValue);
			return NULL;
		}
		if (pulCount)
			*pulCount = attr.ulValueLen / sizeof(char);
	} else if (rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		printf("Attribute Err: %ld\n", rv);
	}
	return (CK_BYTE_PTR) attr.pValue;
}

void close() {
	printf("Closing session with CK_SESSION_HANDLE %ld ...\r\n", hSession1);
	pFunctions->C_Logout(hSession1);
	pFunctions->C_CloseSession(hSession1);
	pFunctions->C_Finalize(NULL);
	FreeLibrary(hModule);
}
