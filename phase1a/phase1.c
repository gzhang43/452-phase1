#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "phase1.h"

typedef struct PCB {
    USLOSS_Context context;
    int pid;
    char name[MAXNAME];
    int priority;
    int status;
    int(*startFunc)(char*);
    char *arg;
    struct PCB* parent;
    struct PCB* child;
    struct PCB* nextSibling;   
    int filled; // if this pcb is in use by a process
} PCB;

struct PCB processTable[MAXPROC];

int lastAssignedPid;
int currentProcess;
int numProcesses;

void sentinel(void) {
    while (1) {
        if (phase2_check_io() == 0) {
            USLOSS_Console("Deadlock detected.\n");
            USLOSS_Halt(0);
        }
        USLOSS_WaitInt();
    }
}

void launcherFunc(void) {
   struct PCB process = processTable[lastAssignedPid % MAXPROC];
   int ret = process.startFunc(process.arg);
   //TODO: Call quit here for returned startFunc()
}

void init_main(void) {
    phase2_start_service_processes();
    phase3_start_service_processes();
    phase4_start_service_processes();
    phase5_start_service_processes();

    fork1("testcase_main", testcase_main, NULL, USLOSS_MIN_STACK, 3); 
    //TODO: create sentinel process
    currentProcess = 2;
    USLOSS_ContextSwitch(&processTable[1].context, &processTable[2].context);
}

// Initialize data structures including process table entry for init
void phase1_init(void) {
    for (int i = 0; i < MAXPROC; i++) {
        processTable[i].filled = 0;
    }

    int pid = 1;
    struct PCB init;
    void *stack = malloc(USLOSS_MIN_STACK);
    init.pid = pid;
    init.filled = 1;

    USLOSS_ContextInit(&init.context, stack, USLOSS_MIN_STACK, NULL, init_main);
    processTable[pid] = init;
    lastAssignedPid = 1;
}

void startProcesses(void) {
    USLOSS_Context *old = NULL;
    numProcesses++;
    currentProcess = 1;
    USLOSS_ContextSwitch(old, &processTable[1].context);
}

bool hasEmptySlots() {
    return numProcesses < MAXPROC;
}

int getNextPid() {
    int nextPid = lastAssignedPid + 1;
    while (processTable[nextPid % MAXPROC].filled == 1) {
        nextPid++;
    }
    return nextPid;
}

void addChildToParent(struct PCB parent, struct PCB child) {
    if (parent.child = NULL) {
        parent.child = &child;
    }
    else {
        struct PCB* temp = parent.child;
        parent.child = &child;
        child.nextSibling = temp;
    }
} 

int fork1(char *name, int(*func)(char *), char *arg, int stacksize,
        int priority) {
    if (stacksize < USLOSS_MIN_STACK) {
        return -2;
    }
    else if (((priority < 1 || priority > 5) && 
            strcmp(name, "sentinel") != 0) || name == NULL ||
            func == NULL || strlen(name) > MAXNAME ||
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
    child.startFunc = func;
    child.arg = arg;
    child.parent = &processTable[currentProcess]; 
    child.child = NULL;
    child.nextSibling = NULL;
    child.filled = 1;
    
    lastAssignedPid = pid;
    USLOSS_ContextInit(&child.context, stack, stacksize, NULL, launcherFunc); 
    processTable[pid % MAXPROC] = child;
    
    addChildToParent(processTable[currentProcess % MAXPROC], child);
    return pid;
}

int join(int *status) {
    if (processTable[currentProcess].child == NULL){
	return -2;
    }
}

void quit(int status, int switchToPid) {

}

int getpid(void) {
    return currentProcess;
}

void dumpProcesses(void) {
    int i = 0;
    while (i < MAXPROC){
	if (&processTable[i] != NULL){
	    USLOSS_Console("\nProcess at index %d", i);
	    USLOSS_Console("\nName: ");
	    USLOSS_Console(processTable[i].name);
	    USLOSS_Console("\npid: %d", processTable[i].pid);
	    USLOSS_Console("\nPriority: %d", processTable[i].priority);
	    USLOSS_Console("\nStatus: %d", processTable[i].status);
	    if (processTable[i].parent != NULL){
		USLOSS_Console("\nParent pid: %d", processTable[i].parent->pid);
	    }
	    if (processTable[i].child != NULL){
		USLOSS_Console("\nChild pid: %d", processTable[i].child->pid);
	    }
	    if (processTable[i].nextSibling != NULL){
		USLOSS_Console("\nNext Sibling pid: %d", 
                    processTable[i].nextSibling->pid);
	    }
	    USLOSS_Console("\n");
	}
	i++;
    }
}

void TEMP_switchTo(int pid) {
    USLOSS_Context *old = &processTable[currentProcess].context;
    currentProcess = pid;
    USLOSS_ContextSwitch(old, &processTable[pid].context);
}
