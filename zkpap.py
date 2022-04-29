import random

def generate_schnorr_prime(q):
    #part of the process of generating the schnorr group
    is_prime = False 
    r = 1 
    p = 0
    while not is_prime:
        p = q*r+1
        is_prime = fermat_prime(p)
        r+=1
    return r,p

def generate_schnorr_group_generator(r,p):
  #find a generator for the schnorr group
  for h in range(2,p):
    if pow(h,r,p) != 1:
      return pow(h,r,p)


def fermat_prime(x):
    #test primality of x with fermats little theorem
    # return (2**(x-1))%x == 1
    return pow(2,(x-1),x) ==1

def miller_rabin(n, k):

    # Implementation uses the Miller-Rabin Primality Test
    # The optimal number of rounds for this test is 40
    # See http://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
    # for justification

    # If number is even, it's a composite number

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1

    if not fermat_prime(n):
      return False
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_prime(max_val=2**64):
  #generate a large random prime number
  is_prime = False

  x = random.randint(0,10**32)

  while not is_prime:
    x-=1
    is_prime = miller_rabin(x,40)
  return x



def generate_schnorr_group_params():
  # generate a large prime and generator for the discrete log problem
  q = generate_large_prime()
  r,p = generate_schnorr_prime(q)
  g = generate_schnorr_group_generator(r,p)
  return g,p



def gen_y(g,p,x):
    # return (g**x)%p 
    return pow(g,x,p)

def gen_r(p):
    return random.randint(0,p-2)

def gen_C(g,p,r):
    # return (g**r)%p 
    return pow(g,r,p)

def prove_1(g,p,r,x):
    return (x+r)%(p-1)

def verify_1(g,p,C,y,ans):
    # return (C*y)%p == (g**ans)%p 
    return (C*y)%p == pow(g,ans,p)

def prove_2(r):
    return r 

def verify_2(g,p,C,ans):
    # return (C) == (g**ans)%p
    return C == pow(g,ans,p)



class Prover:
    def __init__(self,x):
        self.x = x

    def set_g_p(self):
        # generate primes etc 
        g,p = generate_schnorr_group_params()
        self.g = g
        self.p = p 
        return g,p
    
    def gen_y(self):
        self.y = gen_y(self.g,self.p,self.x)
    
    def gen_r(self):
        self.r = gen_r(self.p)

    def gen_C(self):
        self.C = gen_C(self.g,self.p,self.r)

    def prove_1(self):
        return prove_1(self.g,self.p,self.r,self.x)

    def prove_2(self):
        return prove_2(self.r)

    def clean(self):
        self.r = None
        self.C = None 

class Verifier:

    def store_g_p(self,g,p):
        self.g = g
        self.p = p 
    
    def store_C(self,C):
        self.C = C 

    def store_y(self,y):
        self.y = y 

    def verify_1(self,ans):
        return verify_1(self.g,self.p,self.C,self.y,ans)

    def verify_2(self,ans):
        return verify_2(self.g,self.p,self.C,ans)

    def clean(self):
        self.C = None

class Session:
    def __init__(self,prover,verifier):
        self.prover = prover 
        self.verifier = verifier
    
    def initialize_session(self):

        g,p = self.prover.set_g_p()
        self.verifier.store_g_p(g,p)
        self.prover.gen_y()
        self.verifier.store_y(self.prover.y)
    
    def check(self):
        self.prover.gen_r()
        self.prover.gen_C()
        self.verifier.store_C(self.prover.C)
        rand_challenge = random.randint(0,1)
        if rand_challenge == 0:
            res = self.verifier.verify_1(self.prover.prove_1())
            # print('1',self.prover.prove_1())
            self.verifier.clean()
            self.prover.clean()
            return res 
        elif rand_challenge == 1:
            res = self.verifier.verify_2(self.prover.prove_2())
            # print('2',self.prover.prove_1())
            self.verifier.clean()
            self.prover.clean()
            return res 

    def auth(self,N):
        prob_of_false_positive = 0.5**N
        for i in range(N):
            c = self.check()
            if not c:
                print('authorization failed')
                return False
        print('authorization success')
        return True
        


peg = Prover(abs(hash('password')))
vic = Verifier()
sess = Session(peg,vic)

sess.initialize_session()
sess.auth(100)
