#include "Vkeymgr_perip_tb.h"
int main(int argc, char** argv) {
  Vkeymgr_perip_tb* dut = new Vkeymgr_perip_tb();
  while (true) {
    dut->eval();
    if (!dut->eventsPending()) break;
  }
  delete dut;
  return 0;
}
