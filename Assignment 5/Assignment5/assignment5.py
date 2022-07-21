#!/usr/bin/env python
# coding: utf-8

# In[1]:


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
filename = "pt_text.txt"
f = open(filename,"w+")

def getplaintxt(ctr, labels, binary_text,l):
    return 'ff'*ctr + labels[binary_text[:4]] + labels[binary_text[4:(l+1)]] + 'ff'*(8-ctr-1)

ctr = 0
while( ctr < 8):
    j = 0
    while(j < 128):
        binary_text = getBinaryText(j)
        l = len(binary_text)
        f.write(getplaintxt(ctr,labels,binary_text,l) + " ")
        j += 1
    f.write("\n")
    ctr += 1
f.close()
print("completed generation of plaintext")


# In[ ]:


import pexpect
print("Starting receiving ciphertexts from server")
file_plaintext = open("pt_text.txt", 'r')
child = pexpect.spawn('/usr/bin/ssh students@172.27.26.188')                     
child.expect('students@172.27.26.188\'s password:')
child.sendline('cs641a')
#timeout=50 gives sufficient time to ping server
child.expect('Enter your group name: ', timeout=50) 
child.sendline("Enciphered")
child.expect('Enter password: ', timeout=50)
child.sendline("Curve25519!")
# start with level 5 because the level is solved and cleared on server
child.expect('\r\n\r\n\r\nYou have solved 5 levels so far.\r\nLevel you want to start at: ', timeout=50)
file_ciphertext = open("ct_text.txt",'w')
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

ctr = -1
for line in file_plaintext.readlines():
    x = line.split()
    for l in x:
        child.sendline(l)
        s_name = str(child.before)[48:64]
        file_ciphertext.write(s_name)
        file_ciphertext.write(" ")
        ctr+=1
        child.expect("Slowly, a new text starts*")
        child.sendline("c")
        child.expect('The text in the screen vanishes!')
        if ctr%101 == 0:
            print(ctr," out of 1024 completed")
        
    file_ciphertext.write("\n")
    
import numpy as np
child.sendline("ffffffffffffffmu")
s_name = str(child.before)[48:64]
temp = s_name + " "
# print(temp[np.random()])
file_ciphertext.write(temp)
child.close()
file_ciphertext.close()
file_plaintext.close()
print("completed ciphertext generation")


# In[2]:


import numpy as np
all_code_words = []
with open("ct_text.txt",'r') as f:
    for row in f.readlines():
        words = row.split()
        for word in words:
            all_code_words.append(word)
    
with open("ct_text.txt",'w+') as file:
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


# In[3]:


from pyfinite import ffield
F = ffield.FField(7, gen=0x83, useLUT=-1)


# In[4]:


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
      ans += 1
    elif(power==1):
      ans += base
    elif(power%2 == 1):
      subsolution = Binary_Exponentiation(base,power>>1)
      ans = Product(base,Product(subsolution,subsolution))
    else:
      subsolution = Binary_Exponentiation(base,power>>1)
      ans = Product(subsolution, subsolution)
    # assign value here
    dp[base][power] = ans
    return ans


# In[5]:


def LT(matrix, element_list):
  def vprod(vector, element,bsize):
    res= [0]*bsize
    for i, e in enumerate(vector):
      res[i] = Product(e,element)
    return res

  def vsum(v1, v2,bsize):
    res=[0]*bsize
    b = v2
    a = v1
    for i, (x, y) in enumerate(((a[k],b[k]) for k in range(min(len(a),len(b))))):
        res[i] = Sum(x, y)
    return res


  bs = 8
  ans = [0]*bs
  for row, element in zip(matrix, element_list):
    tmp = vprod(row, element,bs)
    ans =  vsum(tmp, ans, bs)
  return ans


# In[6]:


def Sum(num1,num2):
    return num1^num2


# In[7]:


def Product(num1,num2):
    return F.Multiply(num1,num2)


# In[8]:


def getUnicodechar(ciphertext, idx, bs):
  term1 = (2*bs)*(ord(ciphertext[idx:idx+2][0]) - ord('f'))
  term2 = ord(ciphertext[idx:idx+2][1]) - ord('f')
  ans = chr(term1 + term2)
  return ans
  
def decode_block_cipher(ciphertext):
  plaintxt= ""
  i =0
  while(i<len(ciphertext)):
    temp = getUnicodechar(ciphertext, i,8)
    plaintxt +=temp
    i+=2
  return plaintxt


# In[9]:


byte = 8
pos_eps = [[] for i in range(byte)]


# In[10]:


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


# In[11]:


def process_string(index, s):
  ans = []
  for item in s.strip().split():
    decoded_msg = decode_block_cipher(item)
    ans.append(decoded_msg[index])
  return ans

with open("pt_text.txt", 'r') as file1, open("ct_text.txt", 'r') as file2:
  a = file1.readlines()
  b = file2.readlines()
  for index, (input, output) in enumerate((a[i],b[i]) for i in range(min(len(a),len(b)))):

      str_out = process_string(index,output)
      str_inp = process_string(index,input)

      for i in range(1, 127):
        for j in range(1, 128):
          remember = True
          
          bb = str_out
          aa = str_inp
          
          for inp, out in ((aa[k],bb[k]) for k in range(min(len(aa),len(bb))) ):
            case2 = Binary_Exponentiation(Product(Binary_Exponentiation(Product(Binary_Exponentiation(ord(inp), i), j), i), j), i)
            case1 = ord(out)
            if(case2 != case1):
              remember = False
              break
          if(remember):
            pos_diag[index][index].append(j)
            pos_eps[index].append(i)


# In[12]:


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

with open("pt_text.txt", 'r') as file1, open("ct_text.txt", 'r') as file2:
  a = file1.readlines()
  b = file2.readlines()
  for ind, (input, output) in enumerate((a[i],b[i]) for i in range(min(len(a),len(b)))):
      if ind > 6 :
          break
      str_inp = process_ip_string_with_spaces(ind,input)
      str_out = process_op_string_with_spaces(ind,output)

      for i in range(1, 128):
          # aa = pos_eps[ind+1]
          for num1, pow1 in zip(pos_eps[ind+1], pos_diag[ind+1][ind+1]):
              for p2, e2 in zip(pos_eps[ind], pos_diag[ind][ind]):
                  
                  aa = str_inp
                  la = len(aa)
                  remember2 = True
                  bb = str_out
                  lb = len(bb)
                  
                  for inp, outp in ((aa[k],bb[k]) for k in range(min(la,lb))):
                      case1 = Binary_Exponentiation(Sum(Product(Binary_Exponentiation(Product(Binary_Exponentiation(ord(inp), p2), e2), p2), i) ,Product(Binary_Exponentiation(Product(Binary_Exponentiation(ord(inp), p2), i), num1), pow1)), num1)
                      case2 = ord(outp)
                      if(case1 != case2):
                          remember2 = False
                          break
                  if remember2:
                      pos_diag[ind][ind+1] = [i]
                      pos_diag[ind][ind] = [e2]
                      pos_eps[ind] = [p2]
                      pos_diag[ind+1][ind+1] = [pow1]
                      pos_eps[ind+1] = [num1]
                      


# In[13]:


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
  i=0
  for key, val in enumerate(plaintxt):
      i+=1
      output[0][key] = Binary_Exponentiation(val, epnt_matrix[key])
  # print(i,"completed Layer 1")
  i = 0
  output[1] = LT(linear_matrix, output[0])
  i+=1
  # print(i,"completed Layer 2")
  i = 0
  for key, val in enumerate(output[1]):
      i+=1
      output[2][key] = Binary_Exponentiation(val, epnt_matrix[key])
      
  # print(i,"completed Layer 3")
  
  i=0
  output[3] = LT(linear_matrix, output[2])
  i+=1
  # print(i,"completed Layer 3")

  i = 0
  for key, val in enumerate(output[3]):
      i+=1
      output[4][key] = Binary_Exponentiation(val, epnt_matrix[key])
      
  # print(i,"completed Layer 4")    
  return output[4]

def EAEAE (plaintxt, linear_matrix, epnt_matrix): 
  plaintxt = getUnicode(plaintxt)
  ans = LTE(plaintxt,epnt_matrix,linear_matrix)
  return ans


# In[14]:


def process_texts(texts):
    ans = []
    for text in texts.strip().split(' '):
        tmp_decoded = decode_block_cipher(text)
        ans.append(tmp_decoded)
    return ans


# In[15]:



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
      if(len(pos_diag[i][j]) == 0):
        linear_transformation_list[i][j] = 0
      else:
        linear_transformation_list[i][j] = pos_diag[i][j][0]
      j+=1
    i+=1
        

  with open("pt_text.txt", 'r') as file1, open("ct_text.txt", 'r') as output_file:
    a=file1.readlines()
    b=output_file.readlines()
    for key, (input, output) in enumerate((a[i],b[i]) for i in range(min(len(a),len(b)))):
        if(key > (7-ending)):
          continue
        
        ip_str = process_texts(input)
        op_str = process_texts(output)
        i=1
        while(i<128):
            linear_transformation_list[key][key+ending] = i
            remember3 = True
            aa = ip_str
            bb=op_str
            for inps, outs in ((aa[k],bb[k]) for k in range(min(len(aa),len(bb))) ):
                case2 = EAEAE(inps, linear_transformation_list, epnt_list)
                col = key+ending
                case1 = ord(outs[col])
                if case1 != case2[col]:
                    remember3 = False
                    break
            if remember3==True:
                pos_diag[key][col] = [i]
            i+=1
  output_file.close()
  file1.close()
  


# In[16]:



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
      note = len(pos_diag[i][j])
      if note != 0:
        tmp = pos_diag[i][j][0]
      else:
        tmp = 0
      linear_transformation_list[i][j] = tmp 
      j+=1
    i+=1


# In[17]:


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


# In[18]:


block = 8
E_inverse = np.zeros((128, 128), dtype = int)


# In[19]:


A_inverse = np.zeros((block, block), dtype = int)
A_augumented = np.zeros((block, block<<1), dtype = int)


# In[20]:


def getvalue(A, row, col):
    ans = A[row][col]
    return ans
def getvalueFProd(x1,x2):
    return F.Multiply(x1, x2)


# In[21]:


# block = 8
# F = ffield.FField(7, gen=0x83, useLUT=-1)

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
        result = getvalueFProd(temp, base)
        eps[base] += [result]
        epnt += 1
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
i = 0
while(i<block):
    for j in range(0,block):
        A_augumented[i][j] = getvalue(A,i,j)
    A_augumented[i][i+j+1] = int(1)
    i += 1

j = 0
while(j < block):
    pivot_row = np.where(A_augumented[j:,j] != 0)[0][0] + j
    ctr = 0
    # ctr is the loop iterator
    A_augumented[[j, pivot_row]] = A_augumented[[pivot_row, j]]
    
    x2 = inverses[A_augumented[j][j]]
    # ctr = 0
    while(ctr<(block<<1)):
        A_augumented[j][ctr] = F.Multiply(A_augumented[j][ctr], x2)
        ctr+=1
    row= 0
    zrs = 0
    non_zrs = 0
    while(row<block):
        if row!=j and A_augumented[row][j] != 0:
            mult_fact = A_augumented[row][j]
            col = 0
            while(col<(block<<1)):
                temp = F.Multiply(A_augumented[j][col], mult_fact)
                if(temp!=0):
                    non_zrs+=1
                else:
                    zrs+=1
                A_augumented[row][col] = F.Add(temp, A_augumented[row][col])
                col += 1
        row += 1
    j += 1
# print(zrs,non_zrs)
r = 0
while(r<block):
    c=0
    while(c<block):
        A_inverse[r][c] = A_augumented[r][block+c]
        c+=1
    r+=1
#done


# In[22]:


def compute_A_inverse(block, A):
    transformed = []
    elem_sum = 0
    row_num = 0
    while(row_num<8):
        elem_sum = 0
        col_num = 0
        while(col_num<8):
            elem_sum = F.Add(getvalueFProd(A[row_num][col_num],block[col_num]), elem_sum)
            col_num+=1
        row_num+=1
        transformed += [elem_sum]
    return transformed

def compute_E_inverse(block, E):
    j = 0
    transformed = []
    
    while(j<8):
        temp = [E_inverse[E[j]][block[j]]]
        transformed += temp
        j += 1
    return transformed


# In[23]:



encrypted_pwd = "lhkrktlnhojqfhfimjmmlthhgkfhimhj"
num_blocks = int(len(encrypted_pwd) / 16) 

def compute_EA(currentBlock, E, A_inverse):
    temp0 = compute_E_inverse(currentBlock, E)
    temp1 = compute_A_inverse(temp0, A_inverse)
    temp2 = compute_E_inverse(temp1, E)
    temp3 = compute_A_inverse(temp2, A_inverse)
    ans   = compute_E_inverse(temp3, E)
    return ans
    
def getunicode(items, j):
  return (ord(items[j]) - ord('f'))

def getCurrBlock(items):
  ans = []
  j = 0
  while(j<8):
    ans+=[getunicode(items, 2*j)*16 + getunicode(items, 2*j+1)]
    j += 1
  return ans


# In[24]:


A = np.array((A))
block = 16
decrypted_pwd = ""
elements1 = encrypted_pwd[0:16]
currentBlock1 = getCurrBlock(elements1)
ans1 = compute_EA(currentBlock1, E, A_inverse)
for i in range(len(ans1)):
    decrypted_pwd += chr(ans1[i])
elements2 = encrypted_pwd[16:32]
currentBlock2 = getCurrBlock(elements2)
ans2 = compute_EA(currentBlock2, E, A_inverse)
for i in range(len(ans2)):
    decrypted_pwd += chr(ans2[i])


# In[25]:


print("Decrypted Password:",decrypted_pwd[0:10])


# In[ ]:





# In[ ]:




