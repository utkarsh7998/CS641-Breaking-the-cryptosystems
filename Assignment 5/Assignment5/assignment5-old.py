#!/usr/bin/env python
# coding: utf-8

# In[22]:


def getBinaryText(num):
    ans = bin(j)
    ans = ans[2:]
    ans = ans.zfill(8)
    return ans

labels = {
 '0000': 'f',
 '0001': 'g',
 '0010': 'h',
 '0011': 'i',
 '0100': 'j',
 '0101': 'k',
 '0110': 'l',
 '0111': 'm',
 '1000': 'n',
 '1001': 'o',
 '1010': 'p',
 '1011': 'q',
 '1100': 'r',
 '1101': 's',
 '1110': 't',
 '1111': 'u'}

f = open("plaintexts.txt","w+")

i=0
while(i<8):
    j = 0
    while(j < 128):
        binary_text = getBinaryText(j)
        plaintext = 'ff'*i + labels[binary_text[:4]] + labels[binary_text[4:]] + 'ff'*(8-i-1)
        f.write(plaintext + " ")
        j += 1
    f.write("\n")
    i += 1
f.close()
print("completed generation of plaintext")


# In[23]:


import pexpect

child = pexpect.spawn('/usr/bin/ssh students@172.27.26.188')                     
child.expect('students@172.27.26.188\'s password:')
child.sendline('cs641a')
child.expect('Enter your group name: ', timeout=50) 
child.sendline("Enciphered")
child.expect('Enter password: ', timeout=50)
child.sendline("Curve25519!")
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
child.expect('.*')

file_plaintext = open("plaintexts.txt", 'r')
file_ciphertext = open("ciphertexts.txt",'w')
print("Starting known plaintext attack")
i = 0
for line in file_plaintext.readlines():
    x = line.split()
    for l in x:
        child.sendline(l)
        s_name = str(child.before)[48:64]
        file_ciphertext.write(s_name)
        file_ciphertext.write(" ")
        child.expect("Slowly, a new text starts*")
        child.sendline("c")
        child.expect('The text in the screen vanishes!')
        if i%100 == 0:
            print(i)
        i+=1
    file_ciphertext.write("\n")
    

child.sendline("ffffffffffffffmu")
s_name = str(child.before)[48:64]
file_ciphertext.write(s_name)
file_ciphertext.write(" ")

child.close()
file_plaintext.close()
file_ciphertext.close()
print("completed ciphertext generation")


# In[24]:


import numpy as np


# In[25]:


all_code_words = []
with open("ciphertexts.txt",'r') as f:
    for row in f.readlines():
        words = row.split()
        for word in words:
            all_code_words.append(word)
    
with open("ciphertexts.txt",'w+') as file:
    i = 0
    new_text = ""
    for word in all_code_words:
        if(i!=0 and i%128==0):
            file.write(new_text.strip())
            new_text = ""
            file.write('\n')
        new_text+=word
        new_text+=' '
        i+=1
    file.write(new_text.strip())


# In[26]:


from pyfinite import ffield
#a F_128 element will be represented as 7 bit integer i.e. x^2+x+1 = 0000111
F = ffield.FField(7, gen=0x83, useLUT=-1)


# In[27]:


def create_exponents(num):
    x =[]
    for i in range(num):
        x.append([-1]*128)
    return x
dp = create_exponents(128)

def Binary_Exponentiation(base, power):
    if(dp[base][power]!=-1):
      return dp[base][power]
    ans = 0
    if(power==0):
      ans = 1
    elif(power==1):
      ans = base
    elif(power%2 == 1):
      subsolution = Binary_Exponentiation(base,power>>1)
      ans = Product(base,Product(subsolution,subsolution))
    else:
      subsolution = Binary_Exponentiation(base,power>>1)
      ans = Product(subsolution, subsolution)
    
    dp[base][power] = ans
    return ans


# In[28]:


def LT(matrix, element_list):
  def addVectors(v1, v2):
    res=[0]*8
    for i, (x, y) in enumerate(zip(v1, v2)):
        res[i] = Sum(x, y)
    return res

  def mulVectors(vector, element):
    res= [0]*8
    for i, e in enumerate(vector):
      res[i] = Product(e,element)
    return res
  
  ans = [0]*8
  for row, element in zip(matrix, element_list):
    ans = addVectors(mulVectors(row, element), ans)
  return ans


# In[29]:


def LT(matrix, element_list):
  def addVectors(v1, v2):
    res=[0]*8
    a=v1
    b=v2
    for i, (x, y) in enumerate((a[i],b[i]) for i in range(min(len(a),len(b)))):
        res[i] = Sum(x, y)
    return res

  def mulVectors(vector, element):
    res= [0]*8
    for i, e in enumerate(vector):
      res[i] = Product(e,element)
    return res
  
  ans = [0]*8
  for row, element in ((matrix[i], element_list[i]) for i in range(min(len(matrix), len(element_list)))):
    ans = addVectors(mulVectors(row, element), ans)
  return ans


# In[30]:


def Sum(num1,num2):
    return num1^num2


# In[31]:


def Product(num1,num2):
    return F.Multiply(num1,num2)


# In[32]:


def decode_block_cipher(ciphertext):
  plaintxt= ""
  i =0
  while(i<len(ciphertext)):
    temp = chr(16*(ord(ciphertext[i:i+2][0]) - ord('f')) + ord(ciphertext[i:i+2][1]) - ord('f'))
    plaintxt +=temp
    i+=2
  return plaintxt


# In[33]:


byte = 8
pos_eps = [[] for i in range(byte)]


# In[34]:


pos_diag = []
i=0
while(i<8):
    tmp = []
    j = 0
    while(j<8):
        tmp.append([])
        j+=1
    pos_diag.append(tmp)
    i+=1


# In[35]:


def process_string(index, s):
  ans = []
  for item in s.strip().split():
    decoded_msg = decode_block_cipher(item)
    ans.append(decoded_msg[index])
  return ans

with open("plaintexts.txt", 'r') as file1, open("ciphertexts.txt", 'r') as file2:
  a = file1.readlines()
  b = file2.readlines()
  for index, (input, output) in enumerate((a[i],b[i]) for i in range(min(len(a),len(b)))):

      str_out = process_string(index,output)
      str_inp = process_string(index,input)

      for i in range(1, 127):
        for j in range(1, 128):
          flag = True
          aa = str_inp
          bb = str_out
          for inp, out in ((aa[k],bb[k]) for k in range(min(len(aa),len(bb))) ):
            if(ord(out) != Binary_Exponentiation(Product(Binary_Exponentiation(Product(Binary_Exponentiation(ord(inp), i), j), i), j), i)):
              flag = False
              break
          if(flag):
            pos_eps[index].append(i)
            pos_diag[index][index].append(j)


# In[36]:


def process_ip_string_with_spaces(index, s):
  ans = []
  for item in s.strip().split(" "):
    decoded_msg = decode_block_cipher(item)
    ans.append(decoded_msg[index])
  return ans
def process_op_string_with_spaces(index, s):
  ans = []
  for item in s.strip().split(" "):
    decoded_msg = decode_block_cipher(item)
    ans.append(decoded_msg[index+1])
  return ans

with open("plaintexts.txt", 'r') as file1, open("ciphertexts.txt", 'r') as file2:
  a = file1.readlines()
  b = file2.readlines()
  for ind, (input, output) in enumerate((a[i],b[i]) for i in range(min(len(a),len(b)))):
      if ind > 6 :
          break
      str_inp = process_ip_string_with_spaces(ind,input)
      str_out = process_op_string_with_spaces(ind,output)

      for i in range(1, 128):
          for num1, pow1 in zip(pos_eps[ind+1], pos_diag[ind+1][ind+1]):
              for p2, e2 in zip(pos_eps[ind], pos_diag[ind][ind]):
                  flag = True
                  aa = str_inp
                  bb = str_out
                  for inp, outp in ((aa[k],bb[k]) for k in range(min(len(aa),len(bb)))):
                      if(ord(outp) != Binary_Exponentiation(Sum(Product(Binary_Exponentiation(Product(Binary_Exponentiation(ord(inp), p2), e2), p2), i) ,Product(Binary_Exponentiation(Product(Binary_Exponentiation(ord(inp), p2), i), num1), pow1)), num1)):
                          flag = False
                          break
                  if flag:
                      pos_eps[ind+1] = [num1]
                      pos_diag[ind+1][ind+1] = [pow1]
                      pos_eps[ind] = [p2]
                      pos_diag[ind][ind] = [e2]
                      pos_diag[ind][ind+1] = [i]


# In[37]:


def getUnicode(text):
  ans = [ord(i) for i in text]
  return ans

def LTE(plaintxt, epnt_matrix,linear_matrix):
  output = []
  i = 0
  while(i<8):
    temp = []
    j = 0
    while(j<8):
        temp.append(0)
        j += 1
    output.append(temp)
    i += 1

  #Layer1 - Binary_Exponentiation for exponentiation
  for key, val in enumerate(plaintxt):
      output[0][key] = Binary_Exponentiation(val, epnt_matrix[key])

  #Layer2 - LT for Linear Transformation
  output[1] = LT(linear_matrix, output[0])

  #Layer3 - Binary_Exponentiation for epntiation
  for key, val in enumerate(output[1]):
      output[2][key] = Binary_Exponentiation(val, epnt_matrix[key])

  #Layer4 - LT for Linear Transformation
  output[3] = LT(linear_matrix, output[2])

  #Layer5 - Binary_Exponentiation for epntiation
  for key, val in enumerate(output[3]):
      output[4][key] = Binary_Exponentiation(val, epnt_matrix[key])
      
  return output[4]

def EAEAE (plaintxt, linear_matrix, epnt_matrix): 
  plaintxt = getUnicode(plaintxt)
  ans = LTE(plaintxt,epnt_matrix,linear_matrix)
  return ans


# In[38]:



for start in range(0,6):
  ending = start + 2
  
  epnt_list = [e[0] for e in pos_eps]

  linear_transformation_list = []
  
  for j in range(8):
      temp = []
      ctr = 0
      while(ctr<8):
          temp.append(0)
          ctr+=1
      linear_transformation_list.append(temp)
      j+=1
  
  i=0
  while(i<8):
    j=0
    while(j<8):     
      if(len(pos_diag[i][j]) != 0):
        linear_transformation_list[i][j] = pos_diag[i][j][0]
      else:
        linear_transformation_list[i][j] = 0
      j+=1
    i+=1
        

  with open("plaintexts.txt", 'r') as file1, open("ciphertexts.txt", 'r') as output_file:
    a=file1.readlines()
    b=output_file.readlines()
    for key, (input, output) in enumerate((a[i],b[i]) for i in range(min(len(a),len(b)))):
        if(key > (7-ending)):
          continue
        
        ip_str = [decode_block_cipher(msg) for msg in input.strip().split(" ")]
        op_str = [decode_block_cipher(msg) for msg in output.strip().split(" ")]
        i=1
        while(i<128):
            linear_transformation_list[key][key+ending] = i
            label = True
            aa = ip_str
            bb=op_str
            for inps, outs in ((aa[k],bb[k]) for k in range(min(len(aa),len(bb))) ):
                if EAEAE(inps, linear_transformation_list, epnt_list)[key+ending] != ord(outs[key+ending]):
                    label = False
                    break
            if label==True:
                pos_diag[key][key+ending] = [i]
            i+=1
  output_file.close()
  file1.close()
  


# In[39]:



linear_transformation_list = []
j=0
while(j<8):
    temp = []
    i=0
    while(i<8):
        temp.append(0)
        i+=1
    linear_transformation_list.append(temp)
    j+=1

i=0
while(i<8):
    j=0
    while(j<8):
      if len(pos_diag[i][j]) == 0:
        linear_transformation_list[i][j] = 0 
      else:
        linear_transformation_list[i][j] = pos_diag[i][j][0]
      j+=1
    i+=1


# In[40]:


# Computed E and A 
At = linear_transformation_list
E = epnt_list
A = []
i = 0
while(i<len(At[0])):
  j = 0
  temp = []
  while(j<len(At)):
    temp.append(At[j][i])
    j += 1
  A.append(temp)
  i += 1
# A


# In[41]:


block = 8
# F = ffield.FField(7, gen=0x83, useLUT=-1)
A = np.array((A))
A_augumented = np.zeros((block, block*2), dtype = int)
A_inverse = np.zeros((block, block), dtype = int)
E_inverse = np.zeros((128, 128), dtype = int)

eps = []

i=0
while(i<128):
    eps.append([1])
    i+=1

base = 0
while(base<128):
    epnt = 1
    while(epnt<127):
        temp = eps[base][epnt-1]
        result = F.Multiply(temp, base)
        eps[base]+=[result]
        epnt+=1
    base+=1


base = 0
while(base<128):
    epnt = 1
    while(epnt<127):
        E_inverse[epnt][eps[base][epnt]] = base
        epnt+=1
    base+=1

inverses = [1]
ctr = 1
while(ctr<128):
    inverses+=[F.Inverse(ctr)]
    assert F.Multiply(ctr, inverses[ctr]) == int(1)
    ctr+=1

for i in range(0,block):
    for j in range(0,block):
        A_augumented[i][j] = A[i][j]
    A_augumented[i][i+j+1] = int(1)

j = 0
while(j < block):
    # assert np.any(A_augumented[j:,j] != 0) # assert pivot row exists: A is invertible
    pivot_row = np.where(A_augumented[j:,j] != 0)[0][0] + j
    A_augumented[[j, pivot_row]] = A_augumented[[pivot_row, j]]
    mul_fact = inverses[A_augumented[j][j]]
    ctr = 0
    while(ctr<(block<<1)):
        A_augumented[j][ctr] = F.Multiply(A_augumented[j][ctr], mul_fact)
        ctr+=1
    row= 0
    while(row<block):
        if row!=j and A_augumented[row][j] != 0:
            mult_fact = A_augumented[row][j]
            col = 0
            while(col<(block<<1)):
                temp = F.Multiply(A_augumented[j][col], mult_fact)
                A_augumented[row][col] = F.Add(temp, A_augumented[row][col])
                col += 1
        row += 1
    j += 1

r = 0
while(r<block):
    c=0
    while(c<block):
        A_inverse[r][c] = A_augumented[r][block+c]
        c+=1
    r+=1
# print("A inverse matrix: \n{}".format(A_inverse))
#done


# In[42]:


encrypted_pwd = "lhkrktlnhojqfhfimjmmlthhgkfhimhj" #Encrypted encrypted_pwd
block = 16
num_blocks = int(len(encrypted_pwd) / block) # 2 blocks

def compute_E_inverse(block, E):
    transformed = []
    for j in range(0,8):
        transformed+=[E_inverse[E[j]][block[j]]]
    return transformed

def compute_A_inverse(block, A):
    transformed = []
    for row_num in range(0,8):
        elem_sum = 0
        for col_num in range(0,8):
            elem = F.Multiply(A[row_num][col_num], block[col_num])
            elem_sum = F.Add(elem, elem_sum)
        transformed+=[elem_sum]
    return transformed

def compute_EA(currentBlock, E, A_inverse):
    temp0 = compute_E_inverse(currentBlock, E)
    temp1 = compute_A_inverse(temp0, A_inverse)
    temp2 = compute_E_inverse(temp1, E)
    temp3 = compute_A_inverse(temp2, A_inverse)
    ans   = compute_E_inverse(temp3, E)
    return ans
def getCurrBlock(items):
  ans = []
  j = 0
  while(j<8):
    ans+=[(ord(items[2*j]) - ord('f'))*16 + (ord(items[2*j+1]) - ord('f'))]
    j += 1
  return ans

decrypted_pwd = ""
for i in range(0,2): # Decipher both the blocks of the encrypted_pwd
    elements = encrypted_pwd[block*i:block*(i+1)]
    currentBlock = getCurrBlock(elements)
    ans = compute_EA(currentBlock, E, A_inverse)
    for ch in ans:
        decrypted_pwd += chr(ch)
    


# In[43]:


print("Decrypted Password:",decrypted_pwd[0:10])


# In[ ]:




