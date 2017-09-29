import angr
from angr.exploration_techniques import ExplorationTechnique
from itertools import combinations
from BombSquadAnalysis import BombSquadAnalysis

class BombSquad(ExplorationTechnique):

    def __init__(self, analysis):
        super(BombSquad, self).__init__()
        self._INSTRUMENTATION_KEY = 'bombSquadExecutionPath'
        self._LOOPED_FLAG_KEY = 'bombSquadLoopFlag'
        self.analysis = analysis

    # def setup(self):

    def step(self, simgr, stash, **kwargs):
        debug = len(simgr.stashes[stash]) > 10
        print 'stepping', simgr
        for state in simgr.stashes[stash]:
            if self._INSTRUMENTATION_KEY not in state.globals.keys():
                self.analysis.initInstrumentation(state)

        simgr.move(from_stash=stash, to_stash='deferred', filter_func=lambda state: state.globals[self._LOOPED_FLAG_KEY])
        for state in simgr.stashes['deferred']:
            state.globals[self._LOOPED_FLAG_KEY] = False
        if len(simgr.stashes[stash]) == 0:
            print 'no states in loop, pruning'
            statesToPrune = []
            for first, second in combinations(simgr.stashes['deferred'], 2):
                if first in statesToPrune or second in statesToPrune:
                    print 'already pruned one of {} and {}'.format(second.posix.dumps(0), first.posix.dumps(0))
                    continue
                if self.analysis.canCollapseStates(first, second):
                    print 'pruning state with input {} and keeping state with input {}'.format(second.posix.dumps(0), first.posix.dumps(0))
                    statesToPrune.append(second)
                else:
                    print 'not pruning either of {} and {}'.format(second.posix.dumps(0), first.posix.dumps(0))

            simgr.move(from_stash='deferred', to_stash='collapsed', filter_func=lambda state: state in statesToPrune)
            simgr.move(from_stash='deferred', to_stash=stash)

        simgr = simgr.step(stash=stash, n=1, **kwargs)


        return simgr
