import angr
from angr.exploration_techniques import ExplorationTechnique
from itertools import combinations
from BombSquadAnalysis import BombSquadAnalysis

class BombSquad(ExplorationTechnique):

    def __init__(self, analysis):
        super(BombSquad, self).__init__()
        self._LOOPED_FLAG_KEY = 'bombSquadLoopFlag'
        self.analysis = analysis
        self.plugin_whitelist = ['memory', 'registers', 'scratch', 'regs', 'history', 'posix', 'globals', 'inspector', 'unicorn', 'libc', 'mem', 'solver_engine']

    def _do_merge(self, simgr, stash):
        mergedAnything = True
        while mergedAnything is True:
            mergedAnything = False
            mergedStates = []
            newlyMerged = []
            for first, second in combinations(simgr.stashes['deferred'], 2):
                if first in mergedStates or second in mergedStates:
                    continue
                if self.analysis.canCollapseStates(first, second):
                    merged, flag, success = first.merge(second, plugin_whitelist=self.plugin_whitelist)
                    if success:
                        mergedStates.append(first)
                        mergedStates.append(second)
                        newlyMerged.append(merged)
                        mergedAnything = True
            simgr.move(from_stash='deferred', to_stash='merged', filter_func=lambda state: state in mergedStates)
            simgr.stashes['deferred'].extend(newlyMerged)

        simgr.move(from_stash='deferred', to_stash=stash)

    def step(self, simgr, stash, **kwargs):
        debug = len(simgr.stashes[stash]) > 10
        for state in simgr.stashes[stash]:
            if self._LOOPED_FLAG_KEY not in state.globals.keys():
                self.analysis.initInstrumentation(state)

        simgr.move(from_stash=stash, to_stash='deferred', filter_func=lambda state: state.globals[self._LOOPED_FLAG_KEY])
        for state in simgr.stashes['deferred']:
            state.globals[self._LOOPED_FLAG_KEY] = False
        if len(simgr.stashes[stash]) == 0:
            self._do_merge(simgr, stash)

        simgr = simgr.step(stash=stash, n=1, **kwargs)

        return simgr
