import angr
import IPython
from angr.state_plugins.inspect import BP_BEFORE, BP_AFTER
from itertools import combinations, groupby
import claripy

counterValList = []

class BombSquadAnalysis:
    def __init__(self, project, loop):
        self._LOOP_ITERATION_KEY = 'bombSquadLoopIteration'
        self._LOOPED_FLAG_KEY = 'bombSquadLoopFlag'
        self._INSTRUMENTATION_KEY = 'bombSquadExecutionPath'
        self._ORIGINAL_CONSTRAINT_SETS_KEY = 'bombSquadOriginalConstraintSets'
        self.project = project
        self.loop = loop
        state = self.project.factory.blank_state(addr=loop.entry.addr)
        self.simgr = self.project.factory.simgr(state)
        self.initInstrumentation(state)
        self.findCommutativePaths()

    def initInstrumentation(self, state):
        state.globals[self._LOOP_ITERATION_KEY] = 0
        state.globals[self._LOOPED_FLAG_KEY] = False
        state.globals[self._INSTRUMENTATION_KEY] = []

        def incrementLoopCounter(state):
            state.globals[self._LOOP_ITERATION_KEY]+=1
            state.globals[self._LOOPED_FLAG_KEY] = True

        state.inspect.b('instruction', when=BP_BEFORE, instruction=self.loop.entry.addr, action=incrementLoopCounter)

        def logPathTaken(state):
            newPathList = list(state.globals[self._INSTRUMENTATION_KEY])
            newPathList.append(state.block().addr)
            state.globals[self._INSTRUMENTATION_KEY] = newPathList

        for block in self.loop.body_nodes:
            state.inspect.b('instruction', when=BP_BEFORE, instruction=block.addr, action=logPathTaken)

    def findCommutativePaths(self):
        states = self._loopTwice(self.simgr, self.loop)

        self.commutativePaths = []
        self.uniquePaths = []
        for s1, s2 in combinations(states, 2):
            if self._compareStates(s1, s2):
                self.commutativePaths.append((s1, s2))
            else:
                self.uniquePaths.append((s1, s2))

        return self.commutativePaths

    def _getPathHashes(self, state):
        entirePath = list(state.globals[self._INSTRUMENTATION_KEY])
        splitPaths = [list(group) for k, group in groupby(entirePath, lambda x: x == self.loop.entry.addr) if not k]
        # if entirePath[0] != self.loop.entry.addr:
        #     splitPaths = splitPaths[:-1]
        splitPathTuples = [tuple(path) for path in splitPaths]
        splitPathHashes = [hash(t) for t in splitPathTuples]
        return splitPathHashes

    def exitedLoopOrAtEntry(self, state):
        # return lambda state: (state.globals[self._LOOP_ITERATION_KEY] != 0) and (state.block().addr == self.loop.entry.addr or state.block().addr not in [node.addr for node in self.loop.body_nodes])
        if state.globals[self._LOOP_ITERATION_KEY] == 0:
            return False
        if state.block().addr == self.loop.entry.addr:
            return True
        else:
            return state.block().addr not in [node.addr for node in self.loop.body_nodes]

    def canCollapseStates(self, s1, s2):
        if s1.globals[self._LOOP_ITERATION_KEY] != s2.globals[self._LOOP_ITERATION_KEY] or s1.globals[self._LOOP_ITERATION_KEY] == 0:
            return False
        p1 = self._getPathHashes(s1)
        p2 = self._getPathHashes(s2)

        pathsDoCommute = True

        #Length must be equal
        if len(p1) != len(p2):
            return False

        for i in range(len(p1)):
            if p1[i] == p2[i]:
                #we're in great shape
                continue

            if i+1 == len(p1):
                #this means no swap can occur
                pathsDoCommute = False
                break

            if p1[i] == p2[i+1] and self._pathHashesCommute(p2[i], p2[i+1]):
                #we won't ever regret greedily swapping these except in really weird scenarios (branches that do nothing)
                tmp = p2[i+1]
                p2[i+1] = p2[i]
                p2[i] = tmp
                continue

            if p2[i] == p1[i+1] and self._pathHashesCommute(p1[i], p1[i+1]):
                #we won't ever regret greedily swapping these except in really weird scenarios (branches that do nothing)
                tmp = p1[i+1]
                p1[i+1] = p1[i]
                p1[i] = tmp
                continue

            #no way forward. break
            pathsDoCommute = False
            break;

        return pathsDoCommute

    def _pathHashesCommute(self, h1, h2):
        for s1, s2 in self.commutativePaths:
            hashes = self._getPathHashes(s1)
            if h1 in hashes and h2 in hashes:
                return True
            hashes = self._getPathHashes(s2)
            if h1 in hashes and h2 in hashes:
                return True
        return False

    def collapseStates(self, s1, s2):
        commonAncestor = s1.history.closest_common_ancestor(s2)
        s1constraints = s1.constraints_since(s2)
        s2constraints = s2.constraints_since(s1)
        return None

    def _pathSinceAncestor(self, history, ancestorHistory):
        path = []

    def _compareStates(self, s1, s2):
        n_map, n_counter, n_canon_constraint = claripy.And(*s1.se.constraints).canonicalize() #pylint:disable=no-member
        u_map, u_counter, u_canon_constraint = claripy.And(*s2.se.constraints).canonicalize() #pylint:disable=no-member

        # get the differences in registers and memory
        mem_diff = s1.memory.changed_bytes(s2.memory)
        reg_diff = s1.registers.changed_bytes(s2.registers)

        # this is only for unicorn
        if "UNICORN" in s2.options | s1.options:
            if s2.arch.name == "X86":
                reg_diff -= set(range(40, 52)) #ignore cc psuedoregisters
                reg_diff -= set(range(320, 324)) #some other VEX weirdness
                reg_diff -= set(range(340, 344)) #ip_at_syscall
            elif s2.arch.name == "AMD64":
                reg_diff -= set(range(144, 168)) #ignore cc psuedoregisters

        # make sure the differences in memory are actually just renamed
        # versions of the same ASTs
        for diffs,(um,nm) in (
            (mem_diff, (s2.memory, s1.memory)),
        ):
            for i in diffs:
                bn = nm.load(i, 1)
                bu = um.load(i, 1)

                bnc = bn.canonicalize(var_map=n_map, counter=n_counter)[-1]
                buc = bu.canonicalize(var_map=u_map, counter=u_counter)[-1]

                if bnc is not buc:
                    return False
        return True

    def _deactivateStates(self):
        self.simgr.move(filter_func=lambda state: state.block().addr not in self.loopBlocks, from_stash='active', to_stash='exited_loop')
        self.simgr.move(filter_func=lambda state: state.globals[self._LOOP_ITERATION_KEY] > 2, from_stash='active', to_stash='done')

    def _loopTwice(self, simManager, loop):
        self.loopExitBlocks = [finish.addr for start,finish in loop.break_edges]
        self.loopBlocks = [node.addr for node in loop.body_nodes] + self.loopExitBlocks

        while len(simManager.active) != 0:
            self.simgr.step()
            self._deactivateStates()

        return simManager.stashes['done']
