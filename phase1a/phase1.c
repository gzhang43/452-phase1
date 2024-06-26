/*
Assignment: Phase1a
Group: Grace Zhang and Ellie Martin
Course: CSC 452 (Operating Systems)
Instructors: Russell Lewis and Ben Dicken
Due Date: 9/13/23

Description: Code for phase1a of our operating systems kernel that implements
a library for handling processes. Currently contains functions to create processes,
store processes, quit processes and collect them, and to switch between processes.

To compile and run: 
make
./run_testcases.student
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "phase1.h"

void printStatus(int pid);

// PCB struct definition
typedef struct PCB {
    USLOSS_Context context;
    int pid;
    char name[MAXNAME];
    int priority;
    int status;
    int terminated; // 1 = terminated, 0 = alive
    int(*startFunc)(char*);
    char *arg;
    struct PCB* parent;
    struct PCB* child;
    struct PCB* nextSibling;   
    struct PCB* prevSibling;
    void *stack;
    int filled; // if this pcb is in use by a process
} PCB;

struct PCB processTable[MAXPROC+1];

int lastAssignedPid;
int currentProcess; // the pid of the currently running process
int numProcesses;
static char initStack[4*USLOSS_MIN_STACK]; // the stack for the init process

/*
Disables interrupts in the simulation by setting the corresponding bit
in the PSR to 0.
*/
unsigned int disableInterrupts() {
    unsigned int psr = USLOSS_PsrGet();
    int result = USLOSS_PsrSet(USLOSS_PsrGet() & ~2);
    if (result == 1) {
        USLOSS_Console("Error: invalid PSR value for set.\n");
        USLOSS_Halt(1);
    }
    return psr;
}

/*
Restores interrupts in the simulation by setting the PSR to the saved
PSR value.

Parameters:
    savedPsr - the saved PSR value
*/
void restoreInterrupts(int savedPsr) {
    int result = USLOSS_PsrSet(savedPsr);
    if (result == 1) {
        USLOSS_Console("Error: invalid PSR value for set.\n");
        USLOSS_Halt(1);
    } 
}

/*
Enables interrupts in the simulation by setting the corresponding
PSR bit to 1.
*/
void enableInterrupts() {
    int result = USLOSS_PsrSet(USLOSS_PsrGet() | 2);
    if (result == 1) {
        USLOSS_Console("Error: invalid PSR value for set.\n");
        USLOSS_Halt(1);
    } 
}

/*
A function that checks if there is deadlock in the simulation. Runs at 
the lowest priority, so sentinel is only started when all other processes
are blocked. If the blocking is not caused by device drivers, then deadlock
is reported and the simulation is terminated.
*/
void sentinel(void) {
    // If rightmost bit is set to 0, then Psr will be an even int
    if (USLOSS_PsrGet() % 2 == 0) {
        USLOSS_Console("Process is not in kernel mode.\n");
        USLOSS_Halt(1);
    }
    while (1) {
        if (phase2_check_io() == 0) {
            USLOSS_Console("Deadlock detected.\n");
            USLOSS_Halt(0);
        }
        USLOSS_WaitInt();
    }
}

/*
Launcher/trampoline function for user processes. Calls the associated
function using the stored function pointer, and terminates the simulation
with an error if the user function returns.
*/
void launchFunc(void) {
    struct PCB process = processTable[currentProcess % MAXPROC];
    enableInterrupts();
    int ret = process.startFunc(process.arg);
    USLOSS_Console("Error: User function returned.\n");
    USLOSS_Halt(1);
}

/*
Launcher/trampoline function that calls testcase_main. Terminates the 
simulation if testcase_main returns.
*/
void launchTestCaseMain(void) {
    enableInterrupts();
    int ret = (*testcase_main)();
    USLOSS_Console("Phase 1A TEMPORARY HACK: testcase_main() returned, ");
    USLOSS_Console("simulation will now halt.\n");
    USLOSS_Halt(0);
}

/*
Calls start_service_processes for each of the other four phases, and 
creates the sentinel and testcase_main processes using fork1.
*/
void init_main(void) {
    if (USLOSS_PsrGet() % 2 == 0) {
        USLOSS_Console("Process is not in kernel mode.\n");
        USLOSS_Halt(1);
    }
    disableInterrupts(); 
    phase2_start_service_processes();
    phase3_start_service_processes();
    phase4_start_service_processes();
    phase5_start_service_processes();

    fork1("sentinel", NULL, NULL, USLOSS_MIN_STACK, 7);
    fork1("testcase_main", NULL, NULL, USLOSS_MIN_STACK, 3); 
    currentProcess = 3;
    USLOSS_Console("Phase 1A TEMPORARY HACK: init() manually switching to "); 
    USLOSS_Console("testcase_main() after using fork1() to create it.\n");
    USLOSS_ContextSwitch(&processTable[1].context, &processTable[3].context); 
}

/*
Initialize data structures for the program, like the process table, and
create an entry for the process init from the function init_main.
*/
void phase1_init(void) {
    if (USLOSS_PsrGet() % 2 == 0) {
        USLOSS_Console("Process is not in kernel mode.\n");
        USLOSS_Halt(1);
    }
    int savedPsr = disableInterrupts();
    
    for (int i = 0; i < MAXPROC; i++) {
        processTable[i].filled = 0;
    }
    
    int pid = 1;
    struct PCB init;
    void *stack = &initStack;
    init.pid = pid;
    strcpy(init.name, "init");
    init.priority = 6;
    init.filled = 1;

    USLOSS_ContextInit(&init.context, stack, USLOSS_MIN_STACK, NULL, init_main);
    processTable[pid] = init;
    lastAssignedPid = 1;
    restoreInterrupts(savedPsr);
}

/*
Function to start/switch to the init process.
*/
void startProcesses(void) {
    if (USLOSS_PsrGet() % 2 == 0) {
        USLOSS_Console("Process is not in kernel mode.\n");
        USLOSS_Halt(1);
    }
    disableInterrupts(); 
    
    USLOSS_Context *old = NULL;
    numProcesses++;
    currentProcess = 1;
    USLOSS_ContextSwitch(old, &processTable[1].context);
}

/*
Returns true if the process table currently has empty slots and false otherwise.
Used by fork1. 
*/
bool hasEmptySlots() {
    return numProcesses < MAXPROC;
}

/*
Returns the next available pid depending on which slots in the process table
are filled because indexing into the table is done by pid % (table size).
*/
int getNextPid() {
    if (USLOSS_PsrGet() % 2 == 0) {
        USLOSS_Console("Process is not in kernel mode.\n");
        USLOSS_Halt(1);
    }
    int nextPid = lastAssignedPid + 1;
    while (processTable[nextPid % MAXPROC].filled == 1) {
        nextPid++;
    }
    return nextPid;
}

/*
Adds the given child process to the given parent process's list of 
children.

Parameters:
    parent - a PCB struct pointer to the parent process's PCB
    child - a PCB struct pointer to the child process's PCB
*/
void addChildToParent(struct PCB *parent, struct PCB *child) {
    if (parent->child == NULL) {
        parent->child = child;
    }
    else {
        struct PCB* temp = parent->child;
        parent->child = child;
        child->nextSibling = temp;
        temp->prevSibling = child;
    }
} 

/*
Creates a child process of the current process. A PCB entry is created for the
child process with initial information and stored in the process table. The
child process is also added to the current process's list of children.

Parameters:
    name - the name of the process to create; must be under MAXNAME chars
    func - a function pointer to the function of the process to create
    arg - the argument, if any, for the process's function
    stacksize - the size of the stack to be allocated to the process;
                must be at least USLOSS_MIN_STACK
    priority - the priority of the process to create

Returns: -2 if stacksize < USLOSS_MIN_STACK; -1 if there are no empty slots in
the process table, the priority is out of range, the startFunc or name are NULL
(exception for function pointer of testcase_main to signal use of special launch
function), or the name is too long.
*/
int fork1(char *name, int(*func)(char *), char *arg, int stacksize,
        int priority) {
    if (USLOSS_PsrGet() % 2 == 0) {
        USLOSS_Console("ERROR: Someone attempted to call fork1 while in user mode!\n");
        USLOSS_Halt(1);
    } 
    int savedPsr = disableInterrupts(); 
    
    if (stacksize < USLOSS_MIN_STACK) {
        return -2;
    }
    else if (((priority < 1 || priority > 5) && 
            strcmp(name, "sentinel") != 0) || name == NULL ||
            (func == NULL && strcmp(name, "sentinel") != 0 && 
            strcmp(name, "testcase_main") != 0) || strlen(name) > MAXNAME ||
            !hasEmptySlots()) {
        return -1;
    }    
    
    // Create entry in process table
    int pid = getNextPid();
    struct PCB child;
    void *stack = malloc(stacksize);

    child.pid = pid;
    strcpy(child.name, name);
    child.priority = priority;
    child.status = 0; // set status to ready
    child.terminated = 0;
    child.startFunc = func;
    child.arg = arg;
    child.parent = &processTable[currentProcess]; 
    child.child = NULL;
    child.nextSibling = NULL;
    child.prevSibling = NULL;
    child.stack = stack;
    child.filled = 1;
    lastAssignedPid = pid;
    
    // Cases for if process is being created from testcase_main or sentinel
    if (strcmp(name, "testcase_main") == 0) {
        USLOSS_ContextInit(&child.context, stack, stacksize, NULL, launchTestCaseMain);
    }
    else if (strcmp(name, "sentinel") == 0) {
        USLOSS_ContextInit(&child.context, stack, stacksize, NULL, sentinel);
    }
    else {
        USLOSS_ContextInit(&child.context, stack, stacksize, NULL, launchFunc); 
    }

    processTable[pid % MAXPROC] = child; 
    addChildToParent(&processTable[currentProcess % MAXPROC],
        &processTable[pid % MAXPROC]);
    
    numProcesses++;
    restoreInterrupts(savedPsr);
    return pid;
}

/*
Helper function for join to get the pid of a terminated child given a process
PCB. Returns the pid of the first child encountered in the linked list.

Parameters:
    process - the PCB struct pointer of the parent process whose list of 
              children we are searching

Returns: the pid of a terminated child process
*/
int getTerminatedChild(struct PCB *process){
    struct PCB *rootChild = process->child;
    
    struct PCB* temp = rootChild;
    while (temp != NULL) {
        if (temp->terminated == 1) {
            break;
        }
        temp = temp->nextSibling;
    }
    return temp->pid;
}

/*
Helper function for join to remove a dead child from its parent's list
of children. 

Parameters:
    child - a PCB struct pointer to the child PCB to remove
    parent - a PCB struct pointer to the parent PCB
*/
void removeChildFromParent(struct PCB *child, struct PCB *parent) {
    if (child->prevSibling == NULL && child->nextSibling != NULL) {
        parent->child = child->nextSibling; // remove child from head of list
        parent->child->prevSibling = NULL;
    }
    else if (child->prevSibling == NULL && child->nextSibling == NULL) {
        parent->child = NULL;
    }
    else {
        // remove child from list using prevSibling
        struct PCB* temp = child->prevSibling;
        temp->nextSibling = child->nextSibling;
        if (temp->nextSibling != NULL) {
            temp->nextSibling->prevSibling = temp; 
        }
    }
}

/*
Collects a dead child of the current process. If the process
does not have any children, returns -2. The stack of the 
collected process is freed, and its entry in the process
table is also marked as empty.

Parameters:
    status - an out pointer filled with the status of the 
             dead child process joined-to

Returns: -2 if process has no children, or the pid of the
         child joined-to
*/
int join(int *status) {
    if (USLOSS_PsrGet() % 2 == 0) {
        USLOSS_Console("Process is not in kernel mode.\n");
        USLOSS_Halt(1);
    }
    int savedPsr = disableInterrupts(); 
    
    if (processTable[currentProcess % MAXPROC].child == NULL){
	return -2;
    }
    int childPid = getTerminatedChild(&processTable[currentProcess % MAXPROC]);
    // set out-value of status via pointer
    *status = processTable[childPid % MAXPROC].status;

    // free stack of child
    free(processTable[childPid % MAXPROC].stack);
    processTable[childPid % MAXPROC].filled = 0; // set PCB entry to free
    
    removeChildFromParent(&processTable[childPid % MAXPROC], 
        &processTable[currentProcess % MAXPROC]);
    numProcesses--;
    restoreInterrupts(savedPsr);
    return childPid;
}

/*
Terminates the current process by marking the process so that it 
cannot be switched to, and switches to the process with the given
pid. 

Parameters:
    switchToPid - the pid of the process to switch to

Returns: status - the exit status of the quit process
*/
void quit(int status, int switchToPid) {
    if (USLOSS_PsrGet() % 2 == 0) {
        USLOSS_Console("ERROR: Someone attempted to call quit while in user mode!\n");
        USLOSS_Halt(1);
    }
    disableInterrupts(); 
    if (processTable[currentProcess % MAXPROC].child != NULL) {
        USLOSS_Console("ERROR: Process pid %d called quit() ", currentProcess);
        USLOSS_Console("while it still had children.\n");
        USLOSS_Halt(1);
    }
    processTable[currentProcess % MAXPROC].status = status;
    processTable[currentProcess % MAXPROC].terminated = 1;    
    TEMP_switchTo(switchToPid); 
}

/*
Returns the pid of the current running process.
*/
int getpid(void) {
    if (USLOSS_PsrGet() % 2 == 0) {
        USLOSS_Console("Process is not in kernel mode.\n");
        USLOSS_Halt(1);
    }
    int savedPsr = disableInterrupts(); 
    restoreInterrupts(savedPsr);
    return currentProcess;
}

/*
Prints out the following information about the processes in the PCB table:
    PID
    Parent PID (if any)
    Child PID (if any)
    Next Sibling PID (if any)
    Prev Sibling PID (if any)
    Name of the process
    Priority
    State of the process
*/
void dumpProcesses(void) {
    if (USLOSS_PsrGet() % 2 == 0) {
        USLOSS_Console("Process is not in kernel mode.\n");
        USLOSS_Halt(1);
    }
    int savedPsr = disableInterrupts(); 
    USLOSS_Console("PID PPID CPID NSPID PSPID NAME              PRIORITY STATE\n");
    int i = 0;
    while (i < MAXPROC){
	if (processTable[i].filled == 1){
	    USLOSS_Console("%*d ", -3,  processTable[i].pid);
	    if (processTable[i].parent != NULL){
		USLOSS_Console("%*d ", -4, processTable[i].parent->pid);
	    } else {USLOSS_Console("null ");
		}
	    if (processTable[i].child != NULL){
		USLOSS_Console("%*d ", -4, processTable[i].child->pid);
	    } else {USLOSS_Console("null ");
		}
	    if (processTable[i].nextSibling != NULL){
		USLOSS_Console("%*d ", -5, processTable[i].nextSibling->pid);
	    } else {USLOSS_Console("null  ");
		}
	    if (processTable[i].prevSibling != NULL){
		USLOSS_Console("%*d ", -5, processTable[i].prevSibling->pid);
	    } else {USLOSS_Console("null  ");
		}
	    USLOSS_Console("%*s", -18, processTable[i].name);
	    USLOSS_Console("%*d  ", 8, processTable[i].priority);
	    printStatus(i);
	    USLOSS_Console("\n");
	}
	i++;
    }
    restoreInterrupts(savedPsr);
}

/*
Using the status field of the PCB struct, determines the state of a process
with the given parameter pid.
 
If the pid is the pid of the current process, the status is "Running."
If status > 0 and the terminated field is 1, then the process has 
terminated and prints with its status number. If terminated is not 0, 
then the process is "Blocked." If the status is 0, then the process is 
"Runnable."
*/
void printStatus(int pid){
    if (pid == currentProcess){
	USLOSS_Console("Running");
	return;
    }
    if (processTable[pid].status > 0){
	if (processTable[pid].terminated == 1){
	    USLOSS_Console("Terminated(%d)", processTable[pid].status);
	    return;
	}
	USLOSS_Console("Blocked");
	return;
    }
    if (processTable[pid].status == 0){
	USLOSS_Console("Runnable");
    }
}

/*
A temporary function to manually switch from the current process to another 
given process. The state of the current process is saved before context 
switching to the new process.

Parameters:
    int pid - integer representing the pid of the process to switch to
*/
void TEMP_switchTo(int pid) {
    if (USLOSS_PsrGet() % 2 == 0) {
        USLOSS_Console("Process is not in kernel mode.\n");
        USLOSS_Halt(1);
    }
    disableInterrupts(); 
    USLOSS_Context *old = &processTable[currentProcess % MAXPROC].context;
    currentProcess = pid;
    USLOSS_ContextSwitch(old, &processTable[pid % MAXPROC].context);
}
