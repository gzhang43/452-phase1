#include <stdio.h>
#include <stdlib.h>
#include "phase1.h"

typedef struct PCB {
    USLOSS_Context context;
    int pid;
    char name[MAXNAME];
    int priority;
    int status;
    struct PCB* parent;
    struct PCB* child;
    struct PCB* next_sibling;    
} PCB;

struct PCB processTable[MAXPROC];
int currentProcess;
void init_main(void) {
    phase2_start_service_processes();
    phase3_start_service_processes();
    phase4_start_service_processes();
    phase5_start_service_processes();
}

// Initialize data structures including process table entry for init
void phase1_init(void) {
    int pid = 1;
    struct PCB init;
    void *stack = malloc(USLOSS_MIN_STACK);
    init.pid = pid;

    USLOSS_ContextInit(&init.context, stack, USLOSS_MIN_STACK, NULL, init_main);
    processTable[pid] = init;
}

void startProcesses(void) {
    USLOSS_Context *old = NULL;
    currentProcess = 1;
    USLOSS_ContextSwitch(old, &processTable[1].context);
}

int fork1(char *name, int(*func)(char *), char *arg, int stacksize,
        int priority) {
    
}

int join(int *status) {

}

void quit(int status, int switchToPid) {

}

int getpid(void) {
    return processTable[currentProcess].pid;
}

void dumpProcesses(void) {
    int i = 0;
    while (i < MAXPROC){
	if (processTable[i] != NULL){
	    USLOSS_Console("\nProcess at index %d", i);
	    USLOSS_Console("\nName: ");
	    USLOSS_Console(processTable[i].name);
	    USLOSS_Console("\npid: %d", processTable[i].pid);
	    USLOSS_Console("\nPriority: %d", processTable[i].priority);
	    USLOSS_Console("\nStatus: %d", processTable[i].status);
	    if (processTable[i].parent != NULL){
		USLOSS_Console("\nParent pid: %d", processTable[i].parent.pid);
	    }
	    if (processTable[i].child != NULL){
		USLOSS_Console("\nChild pid: %d", processTable[i].child.pid);
	    }
	    if (processTable[i].next_sibling != NULL){
		USLOSS_Console("\nNext Sibling pid: %d", processTable[i].next_sibling.pid);
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
