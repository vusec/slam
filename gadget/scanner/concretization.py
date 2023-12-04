# Custom concretization strategies
#
# Date: November 23, 2023
# Author: Sander Wiebing - Vrije Universiteit Amsterdam

from angr.concretization_strategies import SimConcretizationStrategy

class SimConcretizationStrategyAnyInBounds(SimConcretizationStrategy):
    """
    Concretization strategy that returns any solution within
    (lower_bound, upper_bound)
    """

    def __init__(self, lower_bound, upper_bound, **kwargs):
        super().__init__(**kwargs)
        self.lower_bound = lower_bound
        self.upper_bound = upper_bound

    def _concretize(self, memory, addr, **kwargs):

        child_constraints = (addr >= self.lower_bound, addr <= self.upper_bound)

        kwargs.setdefault("extra_constraints", tuple())
        kwargs["extra_constraints"] += child_constraints


        return self._eval(memory, addr, 1, **kwargs)
