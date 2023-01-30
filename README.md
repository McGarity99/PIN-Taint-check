# PIN-Taint-check

A repository to hold the work for a C++ application that uses
the Intel PIN API to perform taint-checking on bytes entered
through user input.
<br /><br />
The program taints data bytes that enter the control flow via prominent user-input channels such as command-line args, fgets, strcpy, and strncpy. These user-input bytes are stored in a hash data structure. Upon function return, the return address is validated against these tainted bytes. If user-input tainted bytes are used in a return address, then an attack (i.e., buffer overflow) has occurred. At this point, the program prints a detailed error message alerting the user to the attack and halts execution.
<br /><br />
The uthash structure is used for tracking the tainted bytes and the Intel PIN tool is used for instrumentation of functions, which allows for capturing and tracking input parameters as well as return addresses.
