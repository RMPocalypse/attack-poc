# Get the exploit running
Apply the `rmpocalypse.diff` to a clean v6.17 vanilla kernel (torvalds tree).
Configure the kernel such that SEV-SNP is enabled and boot the kernel. 
During boot, the kernel overwrites the self-protecting RMP entry. 
Subsequently, the kernel modules can be used to gain control over the entire RMP.


# Get control over the RMP
Use one of the kernel modules (ToDo) to overwrite the RMP.
