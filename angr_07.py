import angr
import claripy
import sys

project = angr.Project('./07_angr_symbolic_file')
initial_state = project.factory.blank_state(addr = 0x0804887a)

find = 0x080489b0
avoid = 0x08048996

filename ="OJKSQYDP.txt"
symbolic_file_size_bytes =64

symbolic_file_backing_memory = angr.state_plugins.SimSymbolicMemory()
symbolic_file_backing_memory.set_state(initial_state)

password = claripy.BVS('password', symbolic_file_size_bytes * 8)
symbolic_file_backing_memory.store(0, password)

file_options = 'r'
password_file=angr.storage.SimFile(filename,file_options,password,symbolic_file_size_bytes)

symbolic_filesystem = {
filename : password_file
}
initial_state.posix.fs = symbolic_filesystem
simulation = project.factory.simgr(initial_state)

simulation.explore(find =0x080489b0 ,avoid = 0x08048996)

if simulation.found:
    solution_state=simulation.found[0]

    solution = solution_state.solver.eval(password)
    print(solution)
else:
    raise Exception("Are You Using The Right Script?")
