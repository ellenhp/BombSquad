import angr
import IPython
from BombSquad import BombSquad
from BombSquadAnalysis import BombSquadAnalysis

proj = angr.Project("a.out", load_options={"auto_load_libs":False})
proj.analyses.CFG()
lf = proj.analyses.LoopFinder()
analysis = BombSquadAnalysis(proj, lf.loops[0])

proj = angr.Project("a.out", load_options={"auto_load_libs":False})
s = proj.factory.entry_state()
simgr = proj.factory.simgr(s)
simgr.use_technique(BombSquad(analysis))
simgr.run()

IPython.embed()
