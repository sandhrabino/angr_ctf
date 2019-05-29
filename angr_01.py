import angr
import sys

project = angr.Project("./01_angr_avoid")

initial_state = project.factory.entry_state()

simulation = project.factory.simgr(initial_state)


simulation.explore(find = 0x080485e5 , avoid = [ 0x80d4613 , 0x080485a8 ] )
if simulation.found:
    solution_state=simulation.found[0]
    print (solution_state.posix.dumps(sys.stdin.fileno()))
else:
    raise Exception('could not find solution:')
