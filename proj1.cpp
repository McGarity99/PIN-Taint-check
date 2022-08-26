/*
	Author: Hunter McGarity
	CSCI 8240 - Software Security & Cyber Forensics
	UGA Spring 2022
	Dr. Kyu Lee
*/

#include "uthash.h"
#include "pin.H"
#include <iostream>
#include <cstdlib>
#include <bits/stdc++.h>
#include <string>
#include <stack>
#include <vector>

#define MAIN "main"
#define FILENO "fileno"

// Taint the memory if the source of input is stdin
#define FGETS "fgets"
#define GETS "gets"

// Propagate if the src is tainted
#define STRCPY "strcpy@plt"
#define STRNCPY "strncpy@plt"
#define STRCAT "strcat@plt"
#define STRNCAT "strncat@plt"
#define MEMCPY "memcpy@plt"

// Reset tainted memory
#define BZERO "bzero@plt"
#define MEMSET "memset@plt"

//Monitor Calls to build stacktrace

using std::string;
using std::stack;
using std::vector;

//Define global stack for storing stack trace
stack<string> theStack;
stack<string> tempStack;

string main_addr;
string main_caller = "";
bool main_called = true;


//Define struct for tracking tainted bytes
struct byte_track {
	char* tByte;				//key
	stack<string> byteStack;	//val for stack trace
	char* src_b_addr;			//val for addr of function that tainted this byte
	UT_hash_handle hh;			//makes this struct hashable via uthash
};

struct byte_track *bytes_hash = NULL;	//declare the hash

using namespace std;

typedef int ( *FP_FILENO )(FILE*);
FP_FILENO org_fileno;

/*
	This function takes in a char* and adds
	that byte to the data structure,
	thereby tainting it. It also takes in a second
	char* that corresponds to the tainted byte's 
	source byte in the event that the byte was
	tainted from a tainted source in a library call
	such as strcpy().
*/

void add_bytes(char* addr, char* tAddr) {
	struct byte_track *b = new byte_track();
	b->tByte = addr;
	b->byteStack = theStack;
	b->src_b_addr = tAddr;
	HASH_ADD_PTR(bytes_hash, tByte, b);
}

/*
	This function takes in an instance of the data structure
	and removes (untaints) the byte indicated by it.
*/

void untaint_bytes(struct byte_track *record) {
	printf("\nEntering untaint_bytes\n");
	HASH_DEL(bytes_hash, record);
	free(record);
}

/*
	This function uses uthash to find the parameter
	char* within the data structure. Regardless of whether or not
	the char* actualy exists within the structure, the result
	of the HASH_FIND_PTR operation is returned in the temp variable.
*/

struct byte_track* find_bytes(char* addr) {
	char** temp2 = &addr;
	struct byte_track *temp;
	HASH_FIND_PTR(bytes_hash, temp2, temp);
	return temp;
}

/*
	This is the 'master' function for untainting bytes, as called
	by bzeroHead or memcpyHead. It calls the find_bytes() function
	and uses the return value to untaint specified bytes.
*/

void clear(char* nonTaint) {
	struct byte_track *temp = find_bytes(nonTaint);
	untaint_bytes(temp);

} //called by bzeroHead to untaint bytes

/*
	This function prints out the Hash's contents, displaying
	all currently-tainted bytes. 
*/

void print_bytes() {
	struct byte_track *temp;
	for (temp = bytes_hash; temp != NULL; temp = static_cast<byte_track*>(temp->hh.next)) {
		printf("\ttaint byte: %p\n", temp->tByte);
	}
}

/*
	This function returns true if the parameter byte is tainted.
	That is, if it is already present in the Hash.
*/

bool is_tainted(char* testByte) {
	char** testPtr = &testByte;
	struct byte_track *temp;
	HASH_FIND_PTR(bytes_hash, testPtr, temp);
	return (temp != 0); 
}

INT32 Usage() {
		cerr << "This tool detects memory overflow via instrumentation" << endl;
		return -1;
}

/*
	This function simply returns true if its FILE *fd parameter corresponds
	to stdin, and false otherwise.
*/

bool isStdin(FILE *fd) {
		int ret = org_fileno(fd);
		if(ret == 0) return true;
		return false;
}

bool fgets_stdin = false;

/*
	This function, if fgets_stdin == true, will taint all bytes that came in from
	stdin during the call to fgets().
*/

VOID fgetsTail(char* ret, ADDRINT f_addr) {
		if(fgets_stdin) {

				char buf[15];
				sprintf(buf, "0x%x", f_addr);
				unsigned int end = 0;
				for (char* i = ret; end < strlen(ret); i++) {
					add_bytes(i, buf);		
					end++;
				}
		}
		fgets_stdin = false;
}

/*
	This function is instrumented just before a call to fgets().
	It will test to see if the FILE *stream parameter is stdin.
	If it is, then the fgets_stdin bool is set to true.
*/

VOID fgetsHead(char* dest, int size, FILE *stream)
{
		if(isStdin(stream)) {
				fgets_stdin = true;
		} 
}

/*
	This function is instrumented just after a call to gets().
	It will taint necessary bytes based on the return value of gets().
*/

VOID getsTail(char* dest, ADDRINT f_addr)
{

		char buf[15];
		sprintf(buf, "0x%x", f_addr);		
		unsigned int end = 0;
		for (char* i = dest; end < strlen(dest); i++) {
			add_bytes(i, buf);
			end++;
		}
}

/*
	This function is instrumented just before the program begins in main().
	It will take in the command-line arguments (if any) and taint them.
*/

VOID mainHead(int argc, char** argv, ADDRINT addr)
{
		char buf[15];
		sprintf(buf, "0x%x", addr);

		for ( int i = 1; i < argc; i++) {
			char * end = argv[i];
			for (unsigned int ii = 0; ii < strlen(argv[i]); ii++) {
				add_bytes(end, buf);
				end++;
			}
		}

		main_addr = buf;
		theStack.push(buf);	
}

/*
	This funciton returns true if the ADDRINT target
	parameter points to an instruction that is in the
	main executable image. It returns false otherwise.
*/

bool IsInMainExec(ADDRINT target) {
	PIN_LockClient();
	RTN rtn = RTN_FindByAddress(target);
	PIN_UnlockClient();

	if (RTN_Valid(rtn) == false) {
		return false;
	}

	SEC sector = RTN_Sec(rtn);
	if (sector == SEC_Invalid()) {
		return false;
	}

	IMG the_img = SEC_Img(sector);
	if (IMG_Valid(the_img) && IMG_IsMainExecutable(the_img)) {
		return true;
	}
	
	return false;
}

/*
	This function pushes an ADDRINT (address) to the
	global stack variable for access later when a new byte is
	tainted. The ADDRINT is first converted to a string.
*/

VOID pushToStack(ADDRINT addr) {
	if (IsInMainExec(addr)) {
		char buf[15];
		sprintf(buf, "0x%x", addr);
		theStack.push(buf);
		tempStack = theStack;
		if (main_called) {
			main_caller = buf;
			main_called = false;
		}
	}		
} 

/*
	This function pops the top entry off the stack
	in the event that the function in question successfully
	returns.
*/

VOID popFromStack(ADDRINT target, ADDRINT op) {
	if (IsInMainExec(target) && !theStack.empty()) {
		theStack.pop();
		tempStack = theStack;
	}
}

/*
	This function is instrumented just before a call to strcpy().
	It will print out the strcpy() destination and src, as well as
	size of the destination buffer. Its primary purpose is to monitor the
	call of strcpy() by analyzing each byte of the src to see if it is tainted.
	If it is tainted, then the function taints the corresponding target byte
	in dest. This process runs until it encounters a \0 byte in the src,
	since strcpy() itself halts on such data.
	
*/

VOID strcpyHead(char* dest, char* src, ADDRINT f_addr)
{
	char buf[15];
	sprintf(buf, "0x%x", f_addr);		
	
	char* srcByte = src;
	char* destByte = dest;

	unsigned int count = 0;
	while (count <= strlen(src)) {		
		if (src[0] == '\0') {
			add_bytes(destByte, srcByte);
			break;
		}
		if (is_tainted(srcByte)) {
			add_bytes(destByte, srcByte);
		}

		count++;
		srcByte++;
		destByte++;
	} 
}

/*
	This function is very similar to the strcpyHead() function,
	but differs in that is an instrumentation for the strncpy()
	library call. It will taint all tainted bytes coming from src
	and going to dest, subject to the constraints of n.
*/


VOID strncpyHead(char* dest, char* src, size_t n, ADDRINT f_addr) {

	char buf[15];
	sprintf(buf, "0x%x", f_addr);
	
	char* srcByte = src;
	char* destByte = dest;
	unsigned int count = 0;
	while (count < n) {
		if (srcByte[count] == '\0') {
			add_bytes(destByte, srcByte);
			break;
		}
		
		if (is_tainted(srcByte)) {
			add_bytes(destByte, srcByte);
		}
		
		count++;
		srcByte++;
		destByte++;
	}

}


/*
	This function is instrumentation for the strcat() library call.
	It taints all bytes moving from a tainted src to the dest.
*/

VOID strcatHead(char* dest, char* src, ADDRINT f_addr) {

	char buf[15];
	sprintf(buf, "0x%x", f_addr);

	char* destByte = dest;
	char* srcByte = src;
	
	unsigned int count = 0;
	while (count <= strlen(src)) {

		if (is_tainted(srcByte)) {
			add_bytes(destByte, srcByte);
		}
		
		count++;
		srcByte++;
		destByte++;
	}
}

/*
	This function is instrumentation for the strncat() library call.
	If a tainted byte is being copied from the src to the dest,
	then the target byte in dest is also tainted. The process continues
	until n many bytes have been tested/tainted.
*/

VOID strncatHead(char* dest, char* src, size_t n, ADDRINT f_addr) {

	char buf[15];
	sprintf(buf, "0x%x", f_addr);
	
	char* destByte = dest;
	char* srcByte = src;

	unsigned int count = 0;
	while (count <= n) {
		if (is_tainted(srcByte)) {
			add_bytes(destByte, srcByte);
		}

		count++;
		srcByte++;
		destByte++;
	}
}

/*
	This function is the intrumentation for the memcpy library
	call. It will iterate through the appropriate number of bytes
	in the src and taint the corresponding dest byte if the src
	byte was tainted already.
*/

VOID memcpyHead(void* dest, void* src, size_t n, ADDRINT f_addr) {

	char buf[15];
	sprintf(buf, "0x%x", f_addr);

	char* srcByte = (char*)src;
	char* destByte = (char*)dest;
	unsigned int count = 0;
	while (count < n) {
		if (is_tainted(srcByte)) {
			add_bytes(destByte, srcByte);	
		}
		count++;		
		srcByte++;
		destByte++;
	}
}

/*
	This function serves as instrumentation for the bzero library
	call, and is responsible for untainting the appropriate number
	and sequence of bytes, thus removing them from the data structure.
	It relies on severl helper functions to accomplish this.
*/

VOID bzeroHead(void* dest, int n) {
	char * end = (char*)dest;
	for (int i = 0; i < n; i++) {
		if (is_tainted(end))
			clear(end);
		end++; 
	}
}

/*
	This function is instrumentation for the memset library call
	and is very similar to the bzeroHead function in that it untaints
	the appropriate number & sequence of bytes.
*/

VOID memsetHead(void* s, int c, size_t n) {
	char * end = (char*)s;
	for (unsigned int i = 0; i < n; i++) {
		if (is_tainted(end)) {
			clear(end);
		}
		end++;
	}
}

/*
	This function serves as intrumentation for when an attack is detected.
	It prints out the error message and necessary information, such as 
	the instruciton address, the target address, and the tainted byte in which the
	target address was stored.
*/

VOID c_flow_head(char* op, char* dest, char* br_target) {
	byte_track* temp;
	HASH_FIND_PTR(bytes_hash, &dest, temp);
	if (temp != 0) {					//if the target destination in question is tainted
		vector<string> tempVec;
		while(temp->byteStack.empty() == false) {
			tempVec.push_back(temp->byteStack.top());
			temp->byteStack.pop();
		}
		printf("******************** Attack Detected ********************\n");
		printf("IndirectBranch (%p): jump to %p, stored in tainted byte (%p)\n", (char*)op, (char*)br_target, (char*)dest);

		printf("Stack 0: History of Mem(%p): ", temp->tByte);
		
		for (int i = tempVec.size() - 1; i >= 0; i--) {
			printf("%s, ", tempVec[i].c_str()); 
		}

		printf("\nStack 1: History of Mem(%p): %s, %s,", temp->src_b_addr, main_caller.c_str(), main_addr.c_str());


		printf("\n***********************************************************\n");

		
		PIN_ExitApplication(0);				//exit application to avoid attack
	}

}

/*
	This function is for the instrumentation/monitoring
	of instructions that change control flow, as well as calls,
	for the purpose of building each byte's stack trace and
	checking if a tainted byte is used in a control flow 
	instruction.
*/

VOID Instruction(INS ins, VOID* v) {
	if (INS_IsMemoryRead(ins) && INS_IsIndirectControlFlow(ins)) {
		
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)c_flow_head,
			IARG_INST_PTR, IARG_MEMORYREAD_EA, 
			IARG_BRANCH_TARGET_ADDR, IARG_END);
	} //for detecting if an attack has occurred

	if (INS_IsCall(ins) && INS_IsControlFlow(ins)) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)pushToStack, IARG_INST_PTR,
			IARG_END);
	} //for building stack trace

	if (INS_IsRet(ins) && INS_IsControlFlow(ins)) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)popFromStack,
			IARG_BRANCH_TARGET_ADDR, IARG_INST_PTR,
			IARG_END);
	} //for removing from stack trace upon return

}

VOID Image(IMG img, VOID *v) {
		RTN rtn;

		rtn = RTN_FindByName(img, FGETS);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)fgetsHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_END);

				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)fgetsTail, 
								IARG_FUNCRET_EXITPOINT_VALUE,
								IARG_INST_PTR,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, GETS);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getsTail,
								IARG_FUNCRET_EXITPOINT_VALUE,
								IARG_INST_PTR,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, STRCPY);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcpyHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_INST_PTR,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, STRNCPY);
		if(RTN_Valid(rtn)) {
			RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strncpyHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_INST_PTR,
								IARG_END);

				RTN_Close(rtn);

		}
		
		rtn = RTN_FindByName(img, STRCAT);
		if(RTN_Valid(rtn)) {
			RTN_Open(rtn);
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcatHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_INST_PTR,
								IARG_END);
			RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, STRNCAT);
		if(RTN_Valid(rtn)) {
			RTN_Open(rtn);
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strncatHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_INST_PTR,
								IARG_END);
			RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, MEMCPY);
		if(RTN_Valid(rtn)) {
			RTN_Open(rtn);
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memcpyHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_INST_PTR,
								IARG_END);

			RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, MEMSET);
		if(RTN_Valid(rtn)) {
			RTN_Open(rtn);
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memsetHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_END);
			RTN_Close(rtn);
		}


		rtn = RTN_FindByName(img, BZERO);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)bzeroHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, MAIN);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)mainHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_INST_PTR,
								IARG_END);
				RTN_Close(rtn);
		}


		rtn = RTN_FindByName(img, FILENO);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				AFUNPTR fptr = RTN_Funptr(rtn);
				org_fileno = (FP_FILENO)(fptr);
				RTN_Close(rtn);
		}
}


int main(int argc, char *argv[])
{
  PIN_InitSymbols();

		if(PIN_Init(argc, argv)){
				return Usage();
		}
		
  IMG_AddInstrumentFunction(Image, 0);
  INS_AddInstrumentFunction(Instruction, 0);
		PIN_StartProgram();

		return 0;
}

