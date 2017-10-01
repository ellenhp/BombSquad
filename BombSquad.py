import angr
from angr.exploration_techniques import ExplorationTechnique
from itertools import combinations
from BombSquadAnalysis import BombSquadAnalysis

class BombSquad(ExplorationTechnique):

    def __init__(self, analysis):
        super(BombSquad, self).__init__()
        self._LOOPED_FLAG_KEY = 'bombSquadLoopFlag'
        self._LOOP_CONTEXT_KEY = 'bombSquadLoopContextKey'
        self.analysis = analysis
        self.deferred_stashes = set()
        self.plugin_whitelist = ['memory', 'registers', 'scratch', 'regs', 'history', 'posix', 'globals', 'inspector', 'unicorn', 'libc', 'mem', 'solver_engine']

    def _do_merge(self, simgr, stash, deferred_stash):
        mergedAnything = True
        while mergedAnything is True:
            mergedAnything = False
            mergedStates = []
            newlyMerged = []
            for first, second in combinations(simgr.stashes[deferred_stash], 2):
                if first in mergedStates or second in mergedStates:
                    continue
                if self.analysis.canCollapseStates(first, second):
                    merged, flag, success = first.merge(second, plugin_whitelist=self.plugin_whitelist)
                    if success:
                        mergedStates.append(first)
                        mergedStates.append(second)
                        newlyMerged.append(merged)
                        mergedAnything = True
            simgr.move(from_stash=deferred_stash, to_stash='merged', filter_func=lambda state: state in mergedStates)
            simgr.stashes[deferred_stash].extend(newlyMerged)

        simgr.move(from_stash=deferred_stash, to_stash=stash)

    def step(self, simgr, stash, **kwargs):
        for state in simgr.stashes[stash]:
            if self._LOOPED_FLAG_KEY not in state.globals.keys():
                self.analysis.initInstrumentation(state)

        deferred_stash = 'deferred'
        simgr.move(from_stash=stash, to_stash=deferred_stash, filter_func=lambda state: state.globals[self._LOOPED_FLAG_KEY])
        for state in simgr.stashes[deferred_stash]:
            state.globals[self._LOOPED_FLAG_KEY] = False

        if len(simgr.stashes[stash]) == 0:
            self._do_merge(simgr, stash, deferred_stash)

        simgr = simgr.step(stash=stash, n=1, **kwargs)

        #Park any states that are about to enter the loop, because we'll want to merge them prior to entering the loop.
        simgr.move(from_stash=stash, to_stash='parked', filter_func=lambda state: self.analysis.atLoopInit(state))

        #If we just parked our last active state, it's time to merge the parked states and get them ready for the next step.
        if len(simgr.stashes[stash]) == 0:
            simgr.merge(stash='parked')
            simgr.move(from_stash='parked', to_stash=stash)

        return simgr
