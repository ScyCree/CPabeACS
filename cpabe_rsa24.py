from hashlib import sha256
from itertools import combinations
from json import dumps

from charm.core.math.integer import integer, randomBits
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.policytree import PolicyParser
from gmpy2 import gcdext

from rsa_abe import RSA_abe


debug = False
hkey = b'ScyCree2020210571'


class CPabe_RSA24(ABEnc):
    def __init__(self):
        ABEnc.__init__(self)
        global rsa
        rsa = RSA_abe()

    def generate_forbidden_set(self, attrs, tree):
        r_sets = []
        count = len(attrs)
        parser = PolicyParser()
        # 生成禁止集
        for i in range(count - 1, 0, -1):
            g_sets = list(combinations(attrs, i))
            for g_set in g_sets:
                g_set = set(g_set)
                if not parser.prune(tree, g_set):
                    for r_set in r_sets:
                        if g_set.issubset(r_set):
                            break
                    else:
                        r_sets.append(g_set)
        return r_sets

    def get_m_with_attr(self, e, c, n):
        r, u1, u2 = gcdext(e[0], e[1])
        s = [u1, u2]
        i = 2
        while r > 1:
            if i >= len(e):
                break
            r, u1, u2 = gcdext(r, e[i])
            for j in range(len(s)):
                s[j] = s[j] * u1
            s.append(u2)
            i += 1
        else:
            m = 1

            for i in range(len(s)):
                m = m * (pow(c[i], s[i], n)) % n
            return m
        return False

    def setup(self, ):

        h = randomBits(1024)
        # (p, q, N, phi_N) = rsa.paramgen(secparam=1024)
        pk = {'h': h}
        # mk = {'p':p,'q':q,'N':N,'phi_N':phi_N}
        mk = {}
        return pk, mk

    def keygen(self, pk, mk, S):
        # 根据属性列表生成私钥，私钥即属性密文掩码
        sk = {k: int.from_bytes(sha256(k.encode() + hkey).digest(), byteorder='big') for k in S}
        return sk

    def encrypt(self, pk, M, policy_str):
        # 构建访问控制树
        parser = PolicyParser()
        tree = parser.parse(policy_str)
        # 取属性列表
        _dictCount = {}
        parser.findDuplicates(tree, _dictCount)
        attrs = list(_dictCount.keys())
        # print('attr:', attrs)
        # 生成禁止集
        r_sets = self.generate_forbidden_set(attrs, tree)
        # 生成e,N
        rsa_pk, rsa_sk = rsa.keygen(r_sets=r_sets, attrs=attrs, secparam=1024)
        e = {k: int(v) for k, v in rsa_pk['e'].items()}
        N = int(rsa_pk['N'])
        # 掩盖M
        m = M % N
        h = integer(pk['h'] % N)
        m = (h + m) % N
        # 生成c
        c = rsa.encrypt(rsa_pk, m)
        c = {k: int(v) for k, v in c.items()}
        # 掩盖c
        for k, v in c.items():
            c_msk = int.from_bytes(sha256(k.encode() + hkey).digest(), byteorder='big') % N
            c[k] = (v + c_msk) % N
        ct = {'e': e, 'c': c, 'N': N, 'attrs': attrs}
        return ct

    def decrypt(self, pk, sk, ct):
        # 取属性
        c = []
        ks = set(sk.keys()) & set(ct['attrs'])
        ct['N'] = integer(ct['N'])
        ct['c'] = {k: integer(v) % ct['N'] for k, v in ct['c'].items()}
        ct['e'] = {k: integer(v) for k, v in ct['e'].items()}

        pk['h'] = integer(pk['h'])
        for k in ks:
            c.append(int((ct['c'][k] - sk[k] % ct['N']) % ct['N']))
        e = [int(ct['e'][k]) for k in ks]
        m = self.get_m_with_attr(e, c, int(ct['N']))
        if m:
            M = int((integer(int(m)) % ct['N'] - pk['h'] % ct['N']) % ct['N'])
            return M
        return False


def s(j):
    print(dumps(j))


def main():
    cpabe = CPabe_RSA24()
    attrs = ['ONE', 'TWO', 'THREE', 'FOUR']
    access_policy = '((one and three) and (two or one))'
    if debug:
        print("Attributes =>", attrs);
        print("Policy =>", access_policy)

    (pk, mk) = cpabe.setup()
    s(pk)

    sk = cpabe.keygen(pk, mk, attrs)
    print("sk :=>", sk)
    s(sk)

    rand_msg = 123456
    if debug: print("msg =>", rand_msg)
    ct = cpabe.encrypt(pk, rand_msg, access_policy)
    if debug: print("\n\nCiphertext...\n")
    print(ct)
    s(ct)

    rec_msg = cpabe.decrypt(pk, sk, ct)
    if debug: print("\n\nDecrypt...\n")
    if debug: print("Rec msg =>", rec_msg)

    assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"
    if debug: print("Successful Decryption!!!")
    print(type(rec_msg))


if __name__ == "__main__":
    debug = True
    main()
