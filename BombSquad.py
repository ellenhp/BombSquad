import angr
from angr.exploration_techniques import ExplorationTechnique
import random

class BombSquad(ExplorationTechnique):
    def __init__(self):
        super(BombSquad, self).__init__()

    def setup(self, pg):
        if 'deferred' not in pg.stashes:
            pg.stashes['deferred'] = []

    def step(self, pg, stash, **kwargs):
        pg = pg.step(stash=stash, **kwargs)
        if len(pg.stashes[stash]) > 1:
            self._random.shuffle(pg.stashes[stash])
            pg.split(from_stash=stash, to_stash='deferred', limit=1)

        if len(pg.stashes[stash]) == 0:
            if len(pg.stashes['deferred']) == 0:
                return pg
            pg.stashes[stash].append(pg.stashes['deferred'].pop())

return pg
