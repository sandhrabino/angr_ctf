import angr
import sys
import claripy
project = angr.Project("./03_angr_symbolic_registers")

start_address =0x08048980
initial_state = project.factory.blank_state(addr = start_address)

pass0 = claripy.BVS( "pass0" , 32)
pass1 = claripy.BVS( "pass1" , 32)
pass2 = claripy.BVS( "pass2" , 32)

simulation = project.factory.simgr(initial_state)
initial_state.regs.eax = pass0
initial_state.regs.ebx = pass1
initial_state.regs.edx = pass2

simulation.explore(find = 0x080489e9 , avoid = 0x080489d7)

if simulation.found:
    solution_state=simulation.found[0]
    sol0 = solution_state.solver.eval(pass0)
    sol1 = solution_state.solver.eval(pass1)
    sol2 = solution_state.solver.eval(pass2)
    solution = "%x %x %x " % (sol0 ,sol1 ,sol2)
    print(solution)

#print(sol0,sol1,sol2)
#solution_state=simulation.found[1]
#solution_state=simulation.found[2]
#print (solution_state.solver.eval(sol0,cast_to=bytes))
#print (solution_state.solver.eval(sol1,cast_to=bytes))
#print (solution_state.solver.eval(sol2,cast_to=bytes))
#win = 0x08049980
#lose = 0x0804996B
