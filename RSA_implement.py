import random
import time
import re
from crack import MillerRabinPrimeCheck
from crack import PrimeFactorsListCleaner
import warnings
warnings.filterwarnings("ignore")

def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

'''
扩展欧几里的算法
计算 ax + by = 1中的x与y的整数解（a与b互质）
'''
def ext_gcd(a, b):
    if b == 0:
        x1 = 1
        y1 = 0
        x = x1
        y = y1
        r = a
        return r, x, y
    else:
        r, x1, y1 = ext_gcd(b, a % b)
        x = y1
        y = x1 - a // b * y1
        return r, x, y

def exp_mode(base, exponent, n):
    bin_array = bin(exponent)[2:][::-1]
    r = len(bin_array)
    base_array = []

    pre_base = base
    base_array.append(pre_base)

    for _ in range(r - 1):
        next_base = (pre_base * pre_base) % n
        base_array.append(next_base)
        pre_base = next_base

    a_w_b = __multi(base_array, bin_array, n)
    return a_w_b % n

def __multi(array, bin_array, n):
    result = 1
    for index in range(len(array)):
        a = array[index]
        if not int(bin_array[index]):
            continue
        result *= a
        result = result % n  # 加快连乘的速度
    return result


def gen_key(p, q):
    n = p * q
    fy = (p - 1) * (q - 1)  # 计算与n互质的整数个数 欧拉函数
    e = 65537  # 选取e   一般选取65537
    # generate d
    a = e
    b = fy
    r, x, y = ext_gcd(a, b)
    # 计算出的x不能是负数
    # 如果是负数，说明p、q、e选取失败
    # 不过可以把x加上fy，使x为正数，才能计算。
    if x < 0:
        x = x + fy
    d = x
    # 返回：   公钥     私钥
    return (n, e), (n, d)


# 加密 m是被加密的信息 加密成为c
def encrypt(m, pubkey):
    n = pubkey[0]
    e = pubkey[1]
    c = []
    for i in m:
        c.append(exp_mode(i, e, n))
    # c = exp_mode(m, e, n)
    return c


# 解密 c是密文，解密为明文m
def decrypt(c, selfkey):
    n = selfkey[0]
    d = selfkey[1]
    m = []
    for i in c:
        m.append(exp_mode(i, d, n))
    # m = exp_mode(c, d, n)
    return m

def getMesList(bitsLen):
    '''需要被加密的信息转化成数字
    对于所有输入数据分成8位一组
    然后分段进行加密，分段解密即可。'''
    listIn = random.getrandbits(bitsLen)
    listIn = bin(listIn)
    str_ = str(listIn)
    str_ = str_[2:]
    listReturn = re.findall(r'.{8}', str_)
    listReturn = [int(x,2) for x in listReturn]
    return listReturn, str_

def generatePrime(bitsLen):
    startPoint = random.getrandbits(bitsLen)
    while MillerRabinPrimeCheck(startPoint)!=True:
        startPoint += 1
    return startPoint


def judgeRSA(m,d):
    if m==d:
        print('解密成功！')
    else:
        print('解密失败！')

def crackRSA(n, c):
    prime = []
    start = time.clock()
    primeDict = PrimeFactorsListCleaner(n)
    elapsed = (time.clock() - start)
    for k,v in primeDict.items():
        prime.append(k)
    pubkey, selfkey = gen_key(prime[0], prime[1])
    d = decrypt(c, selfkey)
    print("破解成功！本次攻破密钥长度为：",len(bin(prime[0]*prime[1])))
    print("p,q分别为：",prime)
    print("用时：",'%.4f'% elapsed,"s" )
    print("被破解后的明文-->%s" % d)
    return prime

if __name__ == "__main__":
    '''公钥私钥中用到的两个大质数p,q 
    随机生成范围为16-32位
    若最低位数超过32则破解时间较长'''
    p = generatePrime(random.randint(32,64))
    q = generatePrime(random.randint(32,64))
    print("随机选择的p为：" ,p, ", 随机选择的q为： ", q)
    '''生成公钥私钥'''
    pubkey, selfkey = gen_key(p, q)
    m, mes1 = getMesList(1000)
    print("待加密信息-->%s" % m)
    # 信息加密，m被加密的信息，c是加密后的信息
    start1 = time.clock()
    c = encrypt(m, pubkey)
    elapsed1 = (time.clock() - start1)
    print("加密速度：", '%.4f'% elapsed1,"s")
    print("被加密后的密文-->%s" % c)
    # 信息解密'
    start2 = time.clock()
    d= decrypt(c, selfkey)
    elapsed2 = (time.clock() - start1)
    print("解密速度：", '%.4f'% elapsed2,"s")
    print("被解密后的明文-->%s" % d)
    judgeRSA(m,d)
    print("*"*100)
    crackRSA(p*q,c)
