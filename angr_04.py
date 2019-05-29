import angr
import sys
import claripy
import monkeyhex
import archinfo

project = angr.Project("./04_angr_symbolic_stack")

password0 = claripy.BVS('password0', 32)
password1 = claripy.BVS('password1', 32)

initial_state = project.factory.blank_state(addr = 0x08048694)
#simulation = project.factory.simgr(initial_state)

#padding_length_in_bytes = 0x14   #ger
#initial_state.regs.esp-= padding_length_in_bytes
#initial_state.regs.ebp-0x1c= padding_length_in_bytes

#initial_state.stack_push(claripy.BVS('password0',32))
#initial_state.stack_push(claripy.BVS('password1',32))

initial_state.memory.store(initial_state.regs.ebp-0xc,password0,endness=archinfo.Endness.LE)
initial_state.memory.store(initial_state.regs.ebp-0x10,password1,endness=archinfo.Endness.LE)

simulation = project.factory.simgr(initial_state)
simulation.explore(find = 0x080486e4 , avoid = 0x080486d2)
if simulation.found:
    solution_state = simulation.found[0]
    
    sol0= solution_state.solver.eval(password0)
    sol1= solution_state.solver.eval(password1)
    solution = "%u %u " % (sol0 ,sol1)
    print(solution)

else:
    raise Exception('could not find solution:')
