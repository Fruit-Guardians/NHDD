#include <cassert>
#include <cstdio>
#include "../src/capture_coordination.hpp"
#include "../src/capture_tuning.hpp"
int main() {
    CaptureCoordination gate;CaptureCoordination::Background scan,publish;
    assert(!gate.busy(1000000) && !scan.due(gate,1000000));
    gate.enter(1000000);assert(gate.busy(10000000));
    assert(scan.due(gate,1000000) && publish.due(gate,1000000));
    assert(!scan.due(gate,2999999) && scan.due(gate,3000000));
    gate.leave(3100000);
    assert(gate.busy(3599999) && !gate.busy(3600000));
    assert(!scan.due(gate,5000000));
    gate.enter(5100000);gate.enter(5200000);gate.leave(5300000);
    assert(gate.busy(10000000));gate.leave(5400000);assert(!gate.busy(6000000));
    CaptureCoordination sustained;CaptureCoordination::Background budget;sustained.enter(1);
    for(uint64_t n=1;n<10000000;n+=1000)(void)budget.due(sustained,n);
    assert(budget.pauses==5);sustained.leave(10000000);
    assert(!budget.due(sustained,11000000));
    try {CaptureCoordination::Lease lease(gate);assert(gate.busy(CaptureCoordination::now()));throw 1;}
    catch(int){}
    assert(!gate.busy(CaptureCoordination::now()+1000000));
    CaptureCoordination quiet;quiet.enter(100);quiet.leave(200);
    assert(quiet.busy(20000199,20000000) && !quiet.busy(20000200,20000000));
    for(int base=-20;base<=19;++base) {
        assert(CaptureTuning::publisher_nice(base,3,false)==base);
        assert(CaptureTuning::publisher_nice(base,0,true)==base);
        const int busy=CaptureTuning::publisher_nice(base,3,true);
        assert(busy>=base && busy<=19);
    }
    assert(CaptureTuning::publisher_nice(20,3,true)==20);
    assert(CaptureTuning::defer_merge(true,false,7,0));
    assert(!CaptureTuning::defer_merge(true,false,8,0));
    assert(!CaptureTuning::defer_merge(true,true,7,0));
    assert(!CaptureTuning::defer_merge(false,false,7,0));
    assert(!CaptureTuning::defer_merge(true,false,4,5));
    std::puts("capture_coordination_test: OK (active/quiet period/bounded pauses/independent budgets/RAII)");
}
