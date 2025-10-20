# SEV-SNP configuration
Follow [AMDs guidline](https://github.com/AMDESE/AMDSEV) on how to configure the system and run SEV-SNP CVMs.

# Get the exploit running
Apply the `rmpocalypse.diff` to a clean v6.12 vanilla kernel (torvalds tree).
Configure the kernel such that SEV-SNP is enabled and boot it. 
During boot, the kernel automatically overwrites the self-protecting RMP entry. 

# Maliciously enable debug mode
Start a SEV-SNP CVM and insert the kernel module in [gctx_overwrite](./gctx_overwrite)  with `make insmod`. This will overwrite the RMP-Table and maliciously enable debug-mode on the SEV-SNP CVM after it has been attested.