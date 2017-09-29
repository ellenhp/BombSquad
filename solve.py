import angr
import IPython
from BombSquad import BombSquad
from BombSquadAnalysis import BombSquadAnalysis

def runTest(veritesting):
    proj = angr.Project("a.out", load_options={"auto_load_libs":False})
    proj.analyses.CFG()
    lf = proj.analyses.LoopFinder()
    analysis = BombSquadAnalysis(proj, lf.loops[1])

    proj = angr.Project("a.out", load_options={"auto_load_libs":False})
    s = proj.factory.entry_state()
    simgr = proj.factory.simgr(s, veritesting=veritesting)
    if not veritesting:
        simgr.use_technique(BombSquad(analysis))
    simgr.run()

    def isBug(state):
        return state.history.events[-1].objects['exit_code'] != 0

    print 'bug inputs found?'
    for state in simgr.deadended:
        # print 'deadended state', state.posix.dumps(0)
        if isBug(state)._model_concrete:
            print 'bug input:', state.posix.dumps(0)
    print 'done printing bug inputs'

print '\nusing veritesting:\n'
runTest(True)
print '\nusing bombsquad:\n'
runTest(False)
