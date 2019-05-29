import angr
import sys

project = angr.Project("./02_angr_find_condition")

initial_state = project.factory.entry_state()

simulation = project.factory.simgr(initial_state)


simulation.explore(find = 0x0804900d , avoid = 0x8048ff6)
if simulation.found:
    solution_state=simulation.found[0]
    print (solution_state.posix.dumps(sys.stdin.fileno()))
else:
    raise Exception('could not find solution:')
