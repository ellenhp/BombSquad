import angr
from angr.exploration_techniques import ExplorationTechnique
from itertools import combinations
from BombSquadAnalysis import BombSquadAnalysis

class BombSquad(ExplorationTechnique):

    def __init__(self, analysis):
        super(BombSquad, self).__init__()
        self._LOOPED_FLAG_KEY = 'bombSquadLoopFlag'
        self.analysis = analysis

    # def setup(self):

    def step(self, simgr, stash, **kwargs):
        debug = len(simgr.stashes[stash]) > 10
        for state in simgr.stashes[stash]:
            if self._LOOPED_FLAG_KEY not in state.globals.keys():
                self.analysis.initInstrumentation(state)

        simgr.move(from_stash=stash, to_stash='deferred', filter_func=lambda state: state.globals[self._LOOPED_FLAG_KEY])
        for state in simgr.stashes['deferred']:
            state.globals[self._LOOPED_FLAG_KEY] = False
        if len(simgr.stashes[stash]) == 0:
            mergedStates = []
            for first, second in combinations(simgr.stashes['deferred'], 2):
                if first in mergedStates or second in mergedStates:
                    continue
                if self.analysis.canCollapseStates(first, second):
                    # merge_conditions = (first.history.constraints_since(commonAncestor), second.history.constraints_since(commonAncestor))
                    merged, flag, success = first.merge(second)
                    if success:
                        mergedStates.append(first)
                        mergedStates.append(second)
                        simgr.stashes['newly_merged'].append(merged)
                    # simgr.merge(stash='to_merge')
                    # print 'merge successful:', len(simgr.stashes['to_merge']) == 1
                    # simgr.move(from_stash='to_merge', to_stash=stash)
            simgr.move(from_stash='deferred', to_stash='collapsed', filter_func=lambda state: state in mergedStates)
            simgr.move(from_stash='deferred', to_stash=stash)
            simgr.move(from_stash='newly_merged', to_stash=stash)

        simgr = simgr.step(stash=stash, n=1, **kwargs)

        return simgr
