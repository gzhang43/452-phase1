/*
Assignment: Phase1B
Group: Grace Zhang and Ellie Martin
Course: CSC 452 (Operating Systems)
Instructors: Russell Lewis and Ben Dicken
Due Date: 9/25/23

Description: Code for phase1a of our operating systems kernel that implements
a library for handling processes. Currently contains functions to create 
processes, store processes, quit processes and collect them, and to switch
between processes.

To compile and run: 
make
./run_testcases.student
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "phase1.h"

#define DEBUG_MODE 0

static void clockHandler(int dev,void *arg);
void runDispatcher();
void addProcessToEndOfQueue(int pid);
void removeProcessFromQueue(int pid);
int isZapped(void);

// PCB struct definition
typedef struct PCB {
    USLOSS_Context context;
    int pid;
    char name[MAXNAME];
    int priority;
    int status;
    int terminated; // 1 = terminated, 0 = alive
    int isZapped; // 1 = zapped, 0 = not zapped
    int isBlocked; // 1 = blocked, 0 = not blocked
    int isBlockedByJoin;
    int isBlockedByZap;
    struct PCB* zappingProcesses; // list of processes zapping this one
    int(*startFunc)(char*);
    char *arg;
    struct PCB* parent;
    struct PCB* child;
    struct PCB* nextSibling;   
    struct PCB* prevSibling;
    struct PCB* nextInQueue;
    struct PCB* prevInQueue;
    struct PCB* nextZapping;
    void *stack;
    int curStartTime;
    int totalTime;
    int exceededTimeSlice;
    int filled; // if this pcb is in use by a process
} PCB;

struct PCB processTable[MAXPROC+1];
struct PCB *runQueues[8];

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
            USLOSS_Console("DEADLOCK DETECTED!  All of the processes have ");
            USLOSS_Console("blocked, but I/O is not ongoing.\n");
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
    quit(0);    
}

/*
Launcher/trampoline function that calls testcase_main. Terminates the 
simulation if testcase_main returns.
*/
void launchTestCaseMain(void) {
    enableInterrupts();
    int ret = (*testcase_main)();

    if (ret == 0) {
        USLOSS_Halt(0);
    }
    else {
        USLOSS_Console("Some error was detected by the testcase.\n");
        USLOSS_Halt(ret);
    }
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
    int savedPsr = disableInterrupts(); 
    phase2_start_service_processes();
    phase3_start_service_processes();
    phase4_start_service_processes();
    phase5_start_service_processes();

    fork1("sentinel", NULL, NULL, USLOSS_MIN_STACK, 7);
    fork1("testcase_main", NULL, NULL, USLOSS_MIN_STACK, 3); 
    
    int status;
    while (1) {
        join(&status);
    }
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

    // Initialize interrupt handlers 
    USLOSS_IntVec[USLOSS_CLOCK_INT] = clockHandler;    

    for (int i = 0; i < MAXPROC; i++) {
        processTable[i].filled = 0;
    }

    currentProcess = 0;
    
    int pid = 1;
    struct PCB init;
    void *stack = &initStack;
    init.pid = pid;
    strcpy(init.name, "init");
    init.priority = 6;
    init.status = 0;
    init.terminated = 0;
    init.isZapped = 0;
    init.isBlocked = 0;
    init.prevInQueue = NULL;
    init.nextInQueue = NULL;
    init.filled = 1;

    USLOSS_ContextInit(&init.context, stack, USLOSS_MIN_STACK, NULL, init_main);
    processTable[pid] = init;
    lastAssignedPid = 1;
    numProcesses++;
    addProcessToEndOfQueue(pid);
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
    runDispatcher();
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
    // char dummy[1000];
    struct PCB *child = &processTable[pid % MAXPROC];
    void *stack = malloc(stacksize);

    child->pid = pid;
    strcpy(child->name, name);
    child->priority = priority;
    child->status = 0; // set status to ready
    child->terminated = 0;
    child->startFunc = func;
    child->arg = arg;
    child->parent = &processTable[currentProcess]; 
    child->child = NULL;
    child->nextSibling = NULL;
    child->prevSibling = NULL;
    child->prevInQueue = NULL;
    child->nextInQueue = NULL;
    child->zappingProcesses = NULL;
    child->nextZapping = NULL;
    child->stack = stack;
    child->filled = 1;
    lastAssignedPid = pid;
    
    // Cases for if process is being created from testcase_main or sentinel
    if (strcmp(name, "testcase_main") == 0) {
        USLOSS_ContextInit(&child->context, stack, stacksize, NULL, 
            launchTestCaseMain);
    }
    else if (strcmp(name, "sentinel") == 0) {
        USLOSS_ContextInit(&child->context, stack, stacksize, NULL, sentinel);
    }
    else {
        USLOSS_ContextInit(&child->context, stack, stacksize, NULL, launchFunc); 
    }

    addChildToParent(&processTable[currentProcess % MAXPROC],
        &processTable[pid % MAXPROC]);
    
    numProcesses++;
    addProcessToEndOfQueue(pid);
    runDispatcher();
    restoreInterrupts(savedPsr);
    return pid;
}

/*
Helper function for join to get the pid of a terminated child given a process
PCB. Returns the pid of the first child encountered in the linked list.

Parameters:
    process - the PCB struct pointer of the parent process whose list of 
              children we are searching

Returns: the pid of a terminated child process, or -1 if not found
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
   
    // Return -1 if terminated child is not found
    if (temp == NULL) {
        return -1;
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
   
    // If no children are terminated, then block and call dispatcher 
    if (childPid == -1) {
        processTable[currentProcess % MAXPROC].isBlockedByJoin = 1;
        processTable[currentProcess % MAXPROC].status = 11;
        processTable[currentProcess % MAXPROC].isBlocked = 1;
        runDispatcher();
        childPid = getTerminatedChild(
            &processTable[currentProcess % MAXPROC]);
    }

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
void quit(int status) {
    if (USLOSS_PsrGet() % 2 == 0) {
        USLOSS_Console("ERROR: Someone attempted to call quit while in user mode!\n");
        USLOSS_Halt(1);
    }
    int savedPsr = disableInterrupts(); 

    if (DEBUG_MODE) {
        USLOSS_Console("Quit started by process %d.\n", currentProcess);
    }

    if (processTable[currentProcess % MAXPROC].child != NULL) {
        USLOSS_Console("ERROR: Process pid %d called quit() ", currentProcess);
        USLOSS_Console("while it still had children.\n");
        USLOSS_Halt(1);
    }
    processTable[currentProcess % MAXPROC].status = status;
    processTable[currentProcess % MAXPROC].terminated = 1;    

    // Unblock everything trying to zap this process
    if (isZapped() == 1){
	struct PCB* zapping = 
            processTable[currentProcess % MAXPROC].zappingProcesses;
        while (zapping != NULL){
	    if (zapping->isBlockedByZap == 1){
		zapping->isBlockedByZap = 0;
                zapping->isBlocked = 0;
                zapping->status = 0;
                addProcessToEndOfQueue(zapping->pid);
	    }
	    zapping = zapping->nextZapping;
	}
	processTable[currentProcess % MAXPROC].isZapped = 0;
        processTable[currentProcess % MAXPROC].zappingProcesses = NULL;
    }

    // Unblock parent if it's waiting in join for a child to terminate    
    if (processTable[currentProcess % MAXPROC].parent->isBlockedByJoin) {
        processTable[currentProcess % MAXPROC].parent->isBlockedByJoin = 0;
        unblockProc(processTable[currentProcess % MAXPROC].parent->pid);
    }
    
    if (DEBUG_MODE) {
        USLOSS_Console("Process dump before quit() calls dispatcher.\n");
        dumpProcesses(); 
    }    
    runDispatcher();
    restoreInterrupts(savedPsr);
}

/*
Returns the pid of the current running process.
*/
int getpid(void) {
    if (USLOSS_PsrGet() % 2 == 0) {
        USLOSS_Console("Process is not in kernel mode.\n");
        USLOSS_Halt(1);
    }
    return currentProcess;
}

/*
Using the status field of the PCB struct, prints the state of a process
with the given parameter pid.
 
If the pid is the pid of the current process, the status is "Running."
If status > 0 and the terminated field is 1, then the process has 
terminated and prints with its status number. If terminated is not 0, 
then the process is "Blocked." If the status is 0, then the process is 
"Runnable."
*/
void printStatus(int index) {
    if (index == currentProcess) {
	USLOSS_Console("Running");
	return;
    }
    if (processTable[index].status > 0) {
	if (processTable[index].terminated == 1) {
	    USLOSS_Console("Terminated(%d)", processTable[index].status);
	    return;
	}
	USLOSS_Console("Blocked");
        if (processTable[index].isBlockedByJoin == 1) {
            USLOSS_Console("(waiting for child to quit)");
        }
        else if (processTable[index].isBlockedByZap) {
            USLOSS_Console("(waiting for zap target to quit)");
        }
        else {
            USLOSS_Console("(%d)", processTable[index].status);
        }
	return;
    }
    if (processTable[index].status == 0) {
	USLOSS_Console("Runnable");
    }
}

/*
Prints out the following information about the processes in the table:
    PID
    Parent PID
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
    USLOSS_Console(" PID  PPID  %-16s  PRIORITY  STATE\n", "NAME");
    int i = 0;
    while (i < MAXPROC){
	if (processTable[i].filled == 1){
	    USLOSS_Console("%4d  ", processTable[i].pid);
	    if (processTable[i].parent != NULL){
		USLOSS_Console("%4d  ", processTable[i].parent->pid);
	    } else {
                USLOSS_Console("%4d  ", 0);
            }
	    USLOSS_Console("%-16s  ", processTable[i].name);
	    USLOSS_Console("%-8d  ", processTable[i].priority);
	    printStatus(i);
	    USLOSS_Console("\n");
	}
	i++;
    }
    restoreInterrupts(savedPsr);
}

void addProcessToEndOfQueue(int pid) {
    struct PCB *process = &processTable[pid % MAXPROC];
    int priority = process->priority;
    
    if (runQueues[priority] == NULL) {
        runQueues[priority] = process;
        return;
    }

    struct PCB *temp = runQueues[priority];
    while (temp->nextInQueue != NULL) {
        temp = temp->nextInQueue;
    }
    temp->nextInQueue = process;
} 

void removeProcessFromQueue(int pid) {
    struct PCB *process = &processTable[pid % MAXPROC];
    int priority = process->priority;

    // If process is in middle of queue 
    if (process->prevInQueue != NULL) {
	process->prevInQueue->nextInQueue = process->nextInQueue;
        if (process->nextInQueue != NULL) {
            process->nextInQueue->prevInQueue = process->prevInQueue;
        }
    }
    // If process is at head of queue
    else {
        if (process->nextInQueue != NULL) {
	    process->nextInQueue->prevInQueue = NULL;
	}
        runQueues[priority] = process->nextInQueue;
    }
    process->nextInQueue = NULL;
    process->prevInQueue = NULL;
}

/*
Code from Phase 1B spec.
*/
int currentTime() {
    int retval;
    int usloss_rc = USLOSS_DeviceInput(USLOSS_CLOCK_DEV, 0, &retval);
    assert(usloss_rc == USLOSS_DEV_OK);
    return retval;
}

void runDispatcher() {
    if (currentProcess > 0) {
        struct PCB *process = &processTable[currentProcess % MAXPROC];
        if (process->exceededTimeSlice == 1 && process->isBlocked == 0 &&
                process->terminated == 0) {
            removeProcessFromQueue(process->pid);
            addProcessToEndOfQueue(process->pid);
        }
        else if (process->isBlocked == 1 || process->terminated == 1) {
            removeProcessFromQueue(process->pid);  
        }
    } 

    // Get the priority of the process to run next
    int i = 1;
    while (i <= 7) {
        if (runQueues[i] != NULL) {
            break;
        }
        i++;
    } 

    // Return if currentProcess is still the highest priority
    if (runQueues[i]->pid == currentProcess) {
        return;
    }

    if (DEBUG_MODE == 1) {
        USLOSS_Console("Switching to %s\n", runQueues[i]->name); 
    }

    // Update total time of current process
    processTable[currentProcess % MAXPROC].totalTime = readtime() +
        currentTime() - readCurStartTime();

    USLOSS_Context *old = &processTable[currentProcess % MAXPROC].context;
    currentProcess = runQueues[i]->pid;
    processTable[currentProcess % MAXPROC].curStartTime = currentTime();
    USLOSS_ContextSwitch(old, &processTable[currentProcess % MAXPROC].context);
}

void zap(int pid) {
    if (USLOSS_PsrGet() % 2 == 0) {
        USLOSS_Console("Process is not in kernel mode.\n");
        USLOSS_Halt(1);
    }

    int savedPsr = disableInterrupts();
    
    if (DEBUG_MODE) {
        dumpProcesses();
    }

    if (pid <= 0) {
	USLOSS_Console("ERROR: Attempt to zap() a PID which is <= 0. ");
        USLOSS_Console("other_pid = 0\n");
	USLOSS_Halt(1);
    }
    else if (pid == 1) {
	USLOSS_Console("ERROR: Attempt to zap() init.\n");
	USLOSS_Halt(1);
    }
    else if (pid == processTable[currentProcess % MAXPROC].pid) {
	USLOSS_Console("ERROR: Attempt to zap() itself.\n");
	USLOSS_Halt(1);
    }
    else if (processTable[pid % MAXPROC].filled == 0 || (pid !=
            processTable[pid % MAXPROC].pid)) {
	USLOSS_Console("ERROR: Attempt to zap() a non-existent process.\n");
	USLOSS_Halt(1);
    }
    else if (processTable[pid % MAXPROC].terminated == 1) {
	USLOSS_Console("ERROR: Attempt to zap() a process that is already ");
        USLOSS_Console("in the process of dying.\n");
	USLOSS_Halt(1);
    }

    processTable[pid % MAXPROC].isZapped = 1;
    struct PCB* zapping = processTable[pid % MAXPROC].zappingProcesses;
    if (zapping == NULL) {
        processTable[pid % MAXPROC].zappingProcesses = 
            &processTable[currentProcess % MAXPROC];
    }
    else {
        struct PCB *temp = zapping;
        processTable[pid % MAXPROC].zappingProcesses = 
            &processTable[currentProcess % MAXPROC];
        processTable[pid % MAXPROC].zappingProcesses->nextZapping = temp;
    }
    processTable[currentProcess % MAXPROC].isBlockedByZap = 1;
    processTable[currentProcess % MAXPROC].status = 12;
    processTable[currentProcess % MAXPROC].isBlocked = 1;
    runDispatcher();
    restoreInterrupts(savedPsr);
}

int isZapped(void) {
    return processTable[currentProcess % MAXPROC].isZapped;
} 

void blockMe(int newStatus) {
    if (USLOSS_PsrGet() % 2 == 0) {
        USLOSS_Console("Process is not in kernel mode.\n");
        USLOSS_Halt(1);
    }
    int savedPsr = disableInterrupts();

    if (newStatus <= 10) {
        USLOSS_Console("ERROR: New status must be greater than 10.\n");
        USLOSS_Halt(1);
    }
    processTable[currentProcess % MAXPROC].status = newStatus;
    processTable[currentProcess % MAXPROC].isBlocked = 1;
    runDispatcher();
    restoreInterrupts(savedPsr);
}

int unblockProc(int pid) {
    if (USLOSS_PsrGet() % 2 == 0) {
        USLOSS_Console("Process is not in kernel mode.\n");
        USLOSS_Halt(1);
    }
    int savedPsr = disableInterrupts(); 
    
    if (processTable[pid % MAXPROC].filled == 0 || 
            processTable[pid % MAXPROC].isBlocked == 0 || 
            processTable[pid % MAXPROC].status <= 10) {
       return -2;  
    }
    processTable[pid % MAXPROC].isBlocked = 0;
    processTable[pid % MAXPROC].status = 0;
    addProcessToEndOfQueue(pid);
    runDispatcher();

    restoreInterrupts(savedPsr);
    return 0;
}

/* this is the interrupt handler for the CLOCK device */
static void clockHandler(int dev,void *arg) {
    if (DEBUG_MODE) {
        USLOSS_Console("clockHandler(): PSR = %d\n", USLOSS_PsrGet());
        USLOSS_Console("clockHandler(): currentTime = %d\n", currentTime());
    }

    /* make sure to call this first, before timeSlice(), since we want to do
     * the Phase 2 related work even if process(es) are chewing up lots of
     * CPU.
     */
    phase2_clockHandler();

    // call the dispatcher if the time slice has expired
    timeSlice();
}

int readCurStartTime(void) {
    return processTable[currentProcess % MAXPROC].curStartTime;
}

int readtime(void) { 
    return processTable[currentProcess % MAXPROC].totalTime;    
}

void timeSlice(void) {
    if (USLOSS_PsrGet() % 2 == 0) {
        USLOSS_Console("Process is not in kernel mode.\n");
        USLOSS_Halt(1); 
    }                   
    int savedPsr = disableInterrupts(); 

    if (DEBUG_MODE) {
        USLOSS_Console("timeSlice started.\n");
    }

    if (currentTime() - readCurStartTime() >= 80) {
        processTable[currentProcess % MAXPROC].exceededTimeSlice = 1; 
        runDispatcher();
    }
    restoreInterrupts(savedPsr);
}
