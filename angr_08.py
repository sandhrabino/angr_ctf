import angr
import claripy
import sys

project = angr.Project('./08_angr_constraints')
initial_state = project.factory.blank_state(addr=0x080485b3)

password = claripy.BVS('password', 16*8)
password_address = 0x804a050
initial_state.memory.store(password_address, password)

simulation = project.factory.simgr(initial_state)
address_to_check_constraint = 0x08048595 , 0x08048694
simulation.explore(find=address_to_check_constraint)
if simulation.found:
    solution_state = simulation.found[0]
    constrained_parameter_address = 0x804a050
    constrained_parameter_size_bytes = 16
    constrained_parameter_bitvector = solution_state.memory.load(
      constrained_parameter_address,
      constrained_parameter_size_bytes
    )
    constrained_parameter_desired_value = 'AUPDNNPROEZRJWKB'
    solution_state.add_constraints(constrained_parameter_bitvector == constrained_parameter_desired_value)
    solution = solution_state.solver.eval(password)
    print(solution)
else:
    raise Exception("Are You Using The Right Script?")
