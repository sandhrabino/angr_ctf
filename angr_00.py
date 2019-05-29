import angr
import sys

project = angr.Project("./00_angr_find")

initial_state = project.factory.entry_state()

simulation = project.factory.simgr(initial_state)


simulation.explore(find=134514293)
if simulation.found:
    solution_state=simulation.found[0]
    print (solution_state.posix.dumps(sys.stdin.fileno()))
else:
    raise Exception('could not find solution:')
