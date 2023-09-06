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
    struct PCB* parent;
    struct PCB* child;
    struct PCB* nextSibling;   
    int filled; // if this pcb is in use by a process
} PCB;

struct PCB processTable[MAXPROC];
int lastAssignedPid;
int currentProcess;

void init_main(void) {
    phase2_start_service_processes();
    phase3_start_service_processes();
    phase4_start_service_processes();
    phase5_start_service_processes();
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
    USLOSS_ContextSwitch(old, &processTable[1].context);
}

bool hasEmptySlots() {
    // TODO: Check if number of processes is less than table size
    return true;
}

int getNextPid() {
    int nextPid = lastAssignedPid + 1;
    while (processTable[nextPid % MAXPROC].filled == 1) {
        nextPid++;
    }
    return nextPid;
}

int fork1(char *name, int(*func)(char *), char *arg, int stacksize,
        int priority) {
    if (stacksize < USLOSS_MIN_STACK) {
        return -2;
    }
    else if ((priority < 1 || priority > 5) || name == NULL ||
            func == NULL || strlen(name) > MAXNAME ||
            !hasEmptySlots()) {
        return -1;
    }    
    
    // Create entry in process table
    int pid = getNextPid();
    struct PCB child;
    void *stack = malloc(stacksize);
    child.pid = pid;
    child.priority = priority;
    strcpy(child.name, name);
    child.parent = &processTable[currentProcess]; 
    child.child = NULL;
    child.nextSibling = NULL;
    child.filled = 1;
}

int join(int *status) {

}

void quit(int status, int switchToPid) {

}

int getpid(void) {

}

void dumpProcesses(void) {

}

void TEMP_switchTo(int pid) {

}
