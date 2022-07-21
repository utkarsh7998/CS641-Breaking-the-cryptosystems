import pexpect

child = pexpect.spawn('/usr/bin/ssh student@65.0.124.36')

child.expect('Enter your group name: ', timeout=50) 
child.sendline("Cipherberg")

child.expect('Enter password: ', timeout=50)
child.sendline("cryplet")

child.expect('\r\n\r\n\r\nYou have solved 5 levels so far.\r\nLevel you want to start at: ', timeout=50)
child.sendline("5")

child.expect('.*')
child.sendline("go")

child.expect('.*')
child.sendline("wave")

child.expect('.*')
child.sendline("dive")

child.expect('.*')
child.sendline("go")

child.expect('.*')
child.sendline("read")
#print(child.before)
child.expect('.*')

f = open("plaintexts.txt", 'r')
f1= open("ciphertexts.txt",'w')

for line in f.readlines():
	li = line.split()
	# print(len(li))
	# print(li[0])
	# print(li[-1])
	for l in li:
		child.sendline(l)
		#print(child.before)
		s = str(child.before)[48:64]
		#print(s)
		f1.write(s)
		f1.write(" ")
		child.expect("Slowly, a new text starts*")
		child.sendline("c")
		child.expect('The text in the screen vanishes!')
	f1.write("\n")

child.sendline("ffffffffffffffmu")
s = str(child.before)[48:64]
f1.write(s)
f1.write(" ")

# data = child.read()
# print(data)
child.close()
# print(child.before, child.after)

f.close()
f1.close()

# f2 = open('output.txt','r')
# f3 = open('output1.txt','w')
# for line in f2.readlines():
# 	f3.writelines(line[48:64]+"\n")

# f3.close()
