/*
	This program can be compiled and ran with the taint-checker to demonstrate
	the process and print out the results.
*/

#include <stdio.h>
#include <iostream>
#include <bits/stdc++.h>
#include <string>

using std::cout;
using std::endl;

int main(int argc, char** argv) {
	
	char mystring[100];
	printf("\n(Test) destination: %p\n", mystring);
	char * ret = fgets(mystring, 100, stdin);
	printf("(Test) fgets ret: %p\n", ret);
	
	char buf2[256] = "hello there";
	printf("(Test) before gets: %s\n", buf2);
	printf("\n(Test) gets dest: %p\n", buf2);
	char * ret2 = gets(buf2);
	printf("(Test) gets return: %p\n", ret2);	
	printf("(Test) gets result: %s\n", ret2);

	char newBuf[100];
	cout << "(Test) strlen(newBuf): " << strlen(newBuf) << endl;
	char * ret4 = strcpy(newBuf, mystring);


	size_t size = 6;
	char strncpyBuf[100];
	printf("\n(Test) strncpyBuf: %p\n", strncpyBuf);
	printf("\n(Test) strncpy src: %p\n", mystring);
	printf("\n(Test) strncpy size: %d\n", size);
	strncpy(strncpyBuf, mystring, size);

	char strcatBuf[100];
	printf("\n(Test) strcatBuf: %p\n", strcatBuf);
	printf("(Test) strcat src: %p\n", mystring);
	char* strcatRet = strcat(strcatBuf, mystring);

	char strncatBuf[100];
	printf("\n(Test) strncatBuf: %p\n", strncatBuf);
	printf("(Test) strncat src: %p\n", mystring);
	char* strncatRet = strncat(strncatBuf, mystring, size);

	char strncpyBuf2[] = "second strncpy buf";
	char strncpyTester[] = "tester";
	char* strncpyTest = strncpy(strncpyBuf2, strncpyTester, strlen(strncpyTester));
	printf("(Test) strncpy test: %s\n", strncpyBuf2);
	printf("(Test) pointer return: %s\n", strncpyTest);

	char memcpyBuf[100] = "memcpy buffer";
	printf("\n(Test) memcpyBuf: %p\n", memcpyBuf);
	printf("(Test) memcpy src: %p\n", mystring);
	void* memcpyRet = memcpy(memcpyBuf, mystring, size);
	printf("(Test) memcpy result: %s\n", memcpyRet);
	printf("(Test) memcpy result addr: %p\n", memcpyRet);

	bzero(newBuf, 4);
	
	printf("(Test) memset s: %p\n", buf2);
	printf("(Test) memset n: %d\n", size);
	memset(buf2, 5, size);
	
return 0;
} //main
