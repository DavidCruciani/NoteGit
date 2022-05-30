

~~~
VBoxManage createvm --name Win11_dut --ostype Windows11_64 --register
~~~

~~~~
VBoxManage modifyvm Win11_dut --cpus 6 --memory 16000 --vram 128
~~~~

~~~~
VBoxManage modifyvm Win11_dut --nic1 nat
~~~~

~~~~
VBoxManage createhd --filename ./Windows11/Win11_dut.vdi --size 52000 --variant Standard 
~~~~

~~~~
VBoxManage storagectl Win11_dut --name "SATA Controller" --add sata --bootable on
~~~~

~~~~
VBoxManage storageattach Win11_dut --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium ./Windows11/Win11_dut.vdi
~~~~

~~~~
VBoxManage storagectl Win11_dut --name "IDE Controller" --add ide
~~~~

~~~~
VBoxManage storageattach Win11_dut --storagectl "IDE Controller" --port 0  --device 0 --type dvddrive --medium ./Win11_dut.iso
~~~~

~~~~
VBoxManage sharedfolder add Win11_dut --name PartageVM --hostpath PartageVM/
~~~~

~~~~
VBoxManage setproperty vrdeauthlibrary "VBoxAuthSimple"
~~~~

~~~~
VBoxManage modifyvm Win11_dut --vrdeauthtype null
~~~~

~~~~
VBoxManage modifyvm Win11_dut --vrde on --vrdeport 3389
~~~~

~~~~
VBoxManage startvm Win11_dut --type headless
~~~~



~~~
VBoxManage storageattach Win11_dut --storagectl "IDE Controller" --port 0  --device 0 --type dvddrive --medium none
~~~

~~~~
VBoxManage storageattach Win11_dut --storagectl "IDE Controller" --port 0  --device 0 --type dvddrive --medium /usr/share/virtualbox/VBoxGuestAdditions.iso
~~~~

