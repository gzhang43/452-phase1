#include <stdio.h>
#include <stdlib.h>
#include "phase1.h"

typedef struct PCB {
    USLOSS_Context* context;
    int pid; 
} PCB;

PCB processTable[MAXPROC];

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
    USLOSS_ContextInit(init.context, stack, USLOSS_MIN_STACK, NULL, &init_main);
    processTable[pid] = init;
}

void startProcesses(void) {
    USLOSS_Context *old;
    USLOSS_ContextSwitch(old, processTable[1].context);
}

int fork1(char *name, int(*func)(char *), char *arg, int stacksize,
        int priority) {
    
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
