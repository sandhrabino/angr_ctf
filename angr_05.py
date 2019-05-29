import angr
import claripy
import sys

project = angr.Project("./05_angr_symbolic_memory")

start_address = 0x080485fe
initial_state = project.factory.blank_state(addr=start_address)

password0 = claripy.BVS('password0', 64)
password1 = claripy.BVS('password1', 64)
password2 = claripy.BVS('password2', 64)
password3 = claripy.BVS('password3', 64)

initial_state.memory.store(0xa1ba1c0, password0)
initial_state.memory.store(0xa1ba1c8, password1)
initial_state.memory.store(0xa1ba1d0, password2)
initial_state.memory.store(0xa1ba1d8, password3)

simulation = project.factory.simgr(initial_state)
simulation.explore(find=0x0804866d, avoid=0x0804865b)
solution_state = simulation.found[0]
sol0= solution_state.solver.eval(password0)
sol1= solution_state.solver.eval(password1)
sol2= solution_state.solver.eval(password2)
sol3= solution_state.solver.eval(password3)
solution = "%x %x %x %x" % (sol0 ,sol1 ,sol2 ,sol3)
print(solution)
#else:
 #   raise Exception('Could not find the solution')
