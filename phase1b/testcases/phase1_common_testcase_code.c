
#include <usloss.h>
#include <phase1.h>

#include <stdio.h>
#include <assert.h>



void startup(int argc, char **argv)
{
    phase1_init();
    startProcesses();
}



USLOSS_PTE *phase5_mmu_pageTable_alloc(int pid)
{
    return NULL;
}

void phase5_mmu_pageTable_free(int pid, USLOSS_PTE *page_table)
{
    assert(page_table == NULL);
}



void phase2_start_service_processes()
{
    USLOSS_Console("%s() called -- currently a NOP\n", __func__);
}

void phase3_start_service_processes()
{
    USLOSS_Console("%s() called -- currently a NOP\n", __func__);
}

void phase4_start_service_processes()
{
    USLOSS_Console("%s() called -- currently a NOP\n", __func__);
}

void phase5_start_service_processes()
{
    USLOSS_Console("%s() called -- currently a NOP\n", __func__);
}



static int check_io_CALL_COUNT = 0;
static int clockHandler_CALL_COUNT = 0;

int phase2_check_io()
{
    check_io_CALL_COUNT++;
    return 0;
}

void phase2_clockHandler()
{
    clockHandler_CALL_COUNT++;
};

void finish(int argc, char **argv)
{
    USLOSS_Console("TESTCASE ENDED: Call counts:   ");

    if (check_io_CALL_COUNT == 0)
        USLOSS_Console("check_io() 0   ");
    else
        USLOSS_Console("check_io() <nonzero>   ");

    if (clockHandler_CALL_COUNT == 0)
        USLOSS_Console("clockHandler() 0\n");
    else
        USLOSS_Console("clockHandler() <nonzero>\n");
}



void test_setup  (int argc, char **argv) {}
void test_cleanup(int argc, char **argv) {}



void TEMP_switchTo(int pid)
{
    USLOSS_Console("This function must never be called!  I simply implemented it to make sure that you had *removed* it from your phase 1 code.\n");
    assert(0);
}

