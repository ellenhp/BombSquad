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

    A = 4014467982249752317
    B = 3970135063068266083
    print 'bug inputs found?'
    for state in simgr.deadended:
        ph = analysis._getPathHashes(state)
        if isBug(state)._model_concrete:
            print 'bug input:', state.posix.dumps(0)
        # else:
        #     print 'ok input: ', state.posix.dumps(0)
    print 'done printing bug inputs'
    print [len(simgr.stashes[s]) for s in simgr.stashes.keys()]

# print '\nusing veritesting:\n'
# runTest(True)
print '\nusing bombsquad:\n'
runTest(False)
